using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Discovery;

public sealed class WindowsSystemDiscovery : ISystemDiscovery
{
    public async Task<SystemSnapshot> InspectAsync(IReadOnlyCollection<string> roots, CancellationToken cancellationToken)
    {
        var tools = new List<ToolObservation>(); var services = new List<ServiceObservation>(); var sites = new List<ApacheSite>(); var findings = new List<Finding>();
        var ports = Array.Empty<int>(); var approved = new List<string>();
        if (roots.Count > 64) findings.Add(new("SYSTEM_ROOT_LIMIT", "Only the first 64 selected local roots are inspected.", VerificationStatus.NotTested));
        foreach (var root in roots.Take(64))
        {
            if (cancellationToken.IsCancellationRequested) break;
            try { var full = DiscoverySafety.FullPath(root); if (Directory.Exists(full) && !DiscoverySafety.HasReparsePoint(full)) approved.Add(full); }
            catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException or NotSupportedException) { findings.Add(new("SYSTEM_SCOPE", "A system-inspection root could not be safely selected.", VerificationStatus.Unsupported)); }
        }
        var admin = false;
        if (OperatingSystem.IsWindows())
        {
            try { using var identity = WindowsIdentity.GetCurrent(); admin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { findings.Add(new("IDENTITY_UNKNOWN", "Administrative status could not be established.", VerificationStatus.NotTested)); }
        }
        try { ports = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(endpoint => endpoint.Port).Distinct().Order().Take(4096).ToArray(); }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException) { findings.Add(new("LISTENERS_UNKNOWN", "TCP listener metadata could not be read.", VerificationStatus.NotTested)); }
        if (OperatingSystem.IsWindows() && !cancellationToken.IsCancellationRequested) InspectServices(services, findings, cancellationToken);
        using var total = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); total.CancelAfter(TimeSpan.FromSeconds(18));
        try
        {
            var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var root in approved)
            {
                total.Token.ThrowIfCancellationRequested();
                foreach (var relative in new[] { "php/php.exe", "php.exe", "apache/bin/httpd.exe", "bin/httpd.exe", "httpd.exe" })
                {
                    var candidate = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
                    if (File.Exists(candidate) && !DiscoverySafety.HasReparsePoint(candidate)) candidates.Add(candidate);
                }
                foreach (var relative in new[] { "apache/conf/httpd.conf", "conf/httpd.conf" })
                {
                    var config = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
                    if (!File.Exists(config)) continue;
                    var parsed = new ApacheConfigurationParser().Parse(config, approved, total.Token); sites.AddRange(parsed.Sites); findings.AddRange(parsed.Findings);
                }
            }
            foreach (var executable in candidates.Take(8))
            {
                total.Token.ThrowIfCancellationRequested(); var php = Path.GetFileName(executable).Equals("php.exe", StringComparison.OrdinalIgnoreCase);
                var args = php ? new[] { "-n", "-v" } : new[] { "-v" };
                var observation = await VersionAsync(php ? "PHP" : "Apache", executable, args, total.Token).ConfigureAwait(false);
                tools.Add(observation);
            }
        }
        catch (OperationCanceledException) { findings.Add(new(cancellationToken.IsCancellationRequested ? "SYSTEM_CANCELLED" : "SYSTEM_TIMEOUT", "System diagnostics stopped at cancellation or the explicit overall timeout.", VerificationStatus.NotTested)); }
        foreach (var site in sites.Where(site => site.Alias?.Contains("phpmyadmin", StringComparison.OrdinalIgnoreCase) == true || site.AliasTarget?.Contains("phpmyadmin", StringComparison.OrdinalIgnoreCase) == true))
        {
            var url = ApacheConfigurationParser.LocalUrl(site);
            if (url is not null) findings.Add(new("PHPMYADMIN_LOCAL_URL", "Configured local phpMyAdmin URL (not requested): " + url, VerificationStatus.Configured, site.ConfigurationPath));
        }
        findings.Add(new("SYSTEM_READ_ONLY", "Only listener/service metadata, bounded static Apache configuration, PHP -n -v and Apache -v were inspected. No service start/stop or HTTP requests were performed.", VerificationStatus.NotTested));
        return new(Environment.OSVersion.VersionString, Environment.UserDomainName + "\\" + Environment.UserName, admin, tools, services, ports, sites.Distinct().ToArray(), findings);
    }

    private static async Task<ToolObservation> VersionAsync(string name, string executable, string[] arguments, CancellationToken cancellationToken)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo { FileName = executable, UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = Path.GetDirectoryName(executable)! } };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(TimeSpan.FromSeconds(4));
        try
        {
            if (!process.Start()) return new(name, executable, "UNKNOWN", VerificationStatus.Error);
            var output = ReadBoundedAsync(process.StandardOutput, timeout.Token); var error = ReadBoundedAsync(process.StandardError, timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var text = await output.ConfigureAwait(false); _ = await error.ConfigureAwait(false);
            // Publish only the recognized version token, never arbitrary subprocess output.
            var match = Regex.Match(text, name == "PHP" ? @"\bPHP\s+(\d+\.\d+\.\d+(?:[-A-Za-z0-9.]*)?)" : @"\bApache/(\d+\.\d+\.\d+(?:[-A-Za-z0-9.]*)?)", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
            return new(name, executable, match.Success ? match.Groups[1].Value : "UNKNOWN", match.Success && process.ExitCode == 0 ? VerificationStatus.Verified : VerificationStatus.NotTested);
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(); } catch (InvalidOperationException) { }
            if (cancellationToken.IsCancellationRequested) throw;
            return new(name, executable, "TIMEOUT", VerificationStatus.NotTested);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException or RegexMatchTimeoutException)
        { return new(name, executable, "UNKNOWN", VerificationStatus.Error); }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var buffer = new char[8192]; var length = 0;
        while (length < buffer.Length)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(length, buffer.Length - length), cancellationToken).ConfigureAwait(false);
            if (count == 0) break; length += count;
        }
        return new string(buffer, 0, length);
    }

    private static void InspectServices(List<ServiceObservation> result, List<Finding> findings, CancellationToken cancellationToken)
    {
        nint manager = 0;
        try
        {
            using var registry = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
            if (registry is null) return; manager = OpenSCManager(null, null, 0x0001);
            foreach (var name in registry.GetSubKeyNames().Take(4096))
            {
                if (cancellationToken.IsCancellationRequested) break;
                if (!Regex.IsMatch(name, @"apache|mysql|maria|postgres|redis|php|w3svc|mssql", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))) continue;
                using var service = registry.OpenSubKey(name, false); if (service is null) continue;
                var image = service.GetValue("ImagePath") as string ?? "";
                var executableMatch = Regex.Match(image, "^\\s*\"([^\"]+)\"|^\\s*(.+?\\.exe)(?:\\s|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
                var executable = executableMatch.Success ? (executableMatch.Groups[1].Success ? executableMatch.Groups[1].Value : executableMatch.Groups[2].Value) : "UNKNOWN";
                var state = "UNKNOWN"; var handle = manager == 0 ? 0 : OpenService(manager, name, 0x0004);
                if (handle != 0)
                {
                    try { if (QueryServiceStatus(handle, out var status)) state = status.CurrentState switch { 1 => "Stopped", 2 => "StartPending", 3 => "StopPending", 4 => "Running", 5 => "ContinuePending", 6 => "PausePending", 7 => "Paused", _ => "UNKNOWN" }; }
                    finally { CloseServiceHandle(handle); }
                }
                result.Add(new(name, service.GetValue("DisplayName") as string ?? name, state, executable));
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException or RegexMatchTimeoutException)
        { findings.Add(new("SERVICE_METADATA", "Some service metadata was unavailable without additional access; no elevation was attempted.", VerificationStatus.NotTested)); }
        finally { if (manager != 0) CloseServiceHandle(manager); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint OpenService(nint manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatus(nint service, out ServiceStatus status);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(nint handle);
}
