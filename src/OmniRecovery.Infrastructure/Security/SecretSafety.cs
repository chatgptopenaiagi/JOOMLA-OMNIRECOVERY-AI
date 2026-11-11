using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Security;

public static class SecretSafety
{
    public static string Redact(string? input)
    {
        if (string.IsNullOrEmpty(input)) return "";
        var s = input.Length > 16000 ? input[..16000] + " [truncated]" : input;
        s = Regex.Replace(s, @"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[private key removed]");
        s = Regex.Replace(s, @"(?i)\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,})\b", "[token removed]");
        s = Regex.Replace(s, @"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", "[password hash removed]");
        s = Regex.Replace(s, @"\$argon2(?:id|i|d)\$[^\s""']+", "[password hash removed]");
        s = Regex.Replace(s, @"(?i)\b(password|passwd|pwd|api[_ -]?key|authorization|access[_ -]?token|secret|cookie)\b\s*[:=]\s*(?:""[^""]*""|'[^']*'|[^\s;,]+)", "$1=[redacted]");
        return s;
    }

    public static string Error(Exception error) => error switch
    {
        OperationCanceledException => "The operation was cancelled. No unconfirmed recovery action was started.",
        UnauthorizedAccessException => "Access was denied. Choose a readable location or supply an authorized connection.",
        TimeoutException => "The operation exceeded its time limit. Review the selected target and retry.",
        ArgumentException => Redact(error.Message),
        InvalidOperationException => Redact(error.Message),
        _ => "The operation could not complete (" + error.GetType().Name + "). Review the connection and evidence status. Secret-bearing exception details are not logged."
    };

    public static void ProtectDirectory(string path)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows()) return;
        var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Windows identity is unavailable.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }
}

public sealed class WindowsCredentialStore : ICredentialStore
{
    private const string Prefix = "JoomlaOmniRecoveryAI/";
    private static string Target(string target)
    {
        if (!Regex.IsMatch(target,@"\A[A-Za-z0-9._-]{1,100}\z")) throw new ArgumentException("Invalid credential identifier.");
        return Prefix+target;
    }
    public void Save(string target,string username,string secret)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows Credential Manager is required.");
        var data=Encoding.Unicode.GetBytes(secret);
        if(data.Length>2500)throw new ArgumentException("The secret exceeds the Windows credential size limit.");
        var ptr=Marshal.AllocHGlobal(Math.Max(data.Length,1));
        try
        {
            Marshal.Copy(data,0,ptr,data.Length);
            var credential=new NativeCredential { Type=1, TargetName=Target(target), UserName=username, CredentialBlobSize=(uint)data.Length, CredentialBlob=ptr, Persist=2 };
            if(!CredWrite(ref credential,0))throw new InvalidOperationException("Windows Credential Manager could not save this credential.");
        }
        finally { for(var i=0;i<data.Length;i++)Marshal.WriteByte(ptr,i,0);Marshal.FreeHGlobal(ptr);Array.Clear(data); }
    }
    public (string Username,string Secret)? Read(string target)
    {
        if(!CredRead(Target(target),1,0,out var ptr))
        {
            if(Marshal.GetLastWin32Error()==1168)return null;
            throw new InvalidOperationException("Windows Credential Manager could not read this application credential.");
        }
        try
        {
            var c=Marshal.PtrToStructure<NativeCredential>(ptr);
            if(c.CredentialBlobSize>2500)throw new InvalidOperationException("Saved credential is too large.");
            return(c.UserName??"",Marshal.PtrToStringUni(c.CredentialBlob,(int)c.CredentialBlobSize/2)??"");
        }
        finally{CredFree(ptr);}
    }
    public void Delete(string target)
    {
        if(!CredDelete(Target(target),1,0)&&Marshal.GetLastWin32Error()!=1168)throw new InvalidOperationException("Windows Credential Manager could not delete this application credential.");
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct NativeCredential
    {
        public uint Flags,Type; [MarshalAs(UnmanagedType.LPWStr)] public string? TargetName; [MarshalAs(UnmanagedType.LPWStr)] public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist,AttributeCount; public IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string? TargetAlias; [MarshalAs(UnmanagedType.LPWStr)] public string? UserName;
    }
    [DllImport("advapi32.dll",EntryPoint="CredWriteW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CredWrite(ref NativeCredential credential,uint flags);
    [DllImport("advapi32.dll",EntryPoint="CredReadW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CredRead(string target,uint type,uint flags,out IntPtr credential);
    [DllImport("advapi32.dll",EntryPoint="CredDeleteW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CredDelete(string target,uint type,uint flags);
    [DllImport("advapi32.dll")] private static extern void CredFree(IntPtr buffer);
}
