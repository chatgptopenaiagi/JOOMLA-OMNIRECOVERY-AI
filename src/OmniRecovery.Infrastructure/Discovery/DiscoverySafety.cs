using System.Text;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Discovery;

internal static class DiscoverySafety
{
    public static string FullPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
            throw new ArgumentException("Only explicit local filesystem paths are supported.");
        var full = Path.GetFullPath(path);
        if (full.StartsWith("\\\\", StringComparison.Ordinal)) throw new ArgumentException("Network paths are not supported.");
        return Path.TrimEndingDirectorySeparator(full);
    }

    public static bool Within(string path, string root) => path.Equals(root, StringComparison.OrdinalIgnoreCase) || path.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    public static bool Approved(string path, IEnumerable<string> roots, IEnumerable<string>? files = null) =>
        roots.Any(root => Within(path, root)) || (files?.Any(file => path.Equals(file, StringComparison.OrdinalIgnoreCase)) ?? false);

    public static bool HasReparsePoint(string path)
    {
        var current = FullPath(path);
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return true;
            current = Path.GetDirectoryName(current);
        }
        return false;
    }

    public static string ReadText(string path, int maxBytes)
    {
        if (HasReparsePoint(path)) throw new IOException("Reparse points are excluded.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length > maxBytes) throw new IOException("File exceeds the inspection limit.");
        var bytes = new byte[maxBytes + 1];
        var count = 0;
        while (count < bytes.Length)
        {
            var read = stream.Read(bytes, count, bytes.Length - count);
            if (read == 0) break;
            count += read;
        }
        if (count > maxBytes) throw new IOException("File exceeds the inspection limit.");
        return Encoding.UTF8.GetString(bytes, 0, count).TrimStart('\uFEFF');
    }

    public static string? LocalUrl(string? raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || !uri.IsLoopback || !string.IsNullOrEmpty(uri.UserInfo)) return null;
        return uri.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/";
    }

    public static Finding Error(string code, string source) => new(code, "The selected item could not be inspected safely; its content was not executed.", VerificationStatus.Error, source);
}
