using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Discovery;

public sealed record ApacheParseResult(IReadOnlyList<ApacheSite> Sites, IReadOnlyList<Finding> Findings, IReadOnlyList<string> FilesRead);

public sealed class ApacheConfigurationParser
{
    private sealed class Context
    {
        public string Configuration = "";
        public string DocumentRoot = "";
        public string Host = "localhost";
        public List<int> Ports = [];
        public bool Https;
        public List<(string Alias, string Target)> Aliases = [];
    }

    public ApacheParseResult Parse(string configurationPath, IReadOnlyCollection<string> approvedRoots, CancellationToken cancellationToken = default)
    {
        var sites = new List<ApacheSite>(); var findings = new List<Finding>(); var files = new List<string>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var active = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var variables = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        var contexts = new List<Context>(); var stack = new Stack<Context>();
        var clock = Stopwatch.StartNew(); string initial; string[] roots;
        try { initial = DiscoverySafety.FullPath(configurationPath); roots = approvedRoots.Select(DiscoverySafety.FullPath).ToArray(); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return new([], [new("APACHE_PATH", "Apache inspection requires a local filesystem scope.", VerificationStatus.Unsupported)], []); }
        var serverRoot = Path.GetDirectoryName(initial)!; var global = new Context { Configuration = initial }; var current = global; var bytes = 0L;

        string? Expand(string value, string source)
        {
            for (var n = 0; n < 8 && value.Contains("${", StringComparison.Ordinal); n++)
            {
                var before = value;
                value = Regex.Replace(value, @"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", match => variables.TryGetValue(match.Groups[1].Value, out var replacement) ? replacement : match.Value, RegexOptions.None, TimeSpan.FromMilliseconds(100));
                if (before == value) break;
            }
            if (value.Contains("${", StringComparison.Ordinal)) { findings.Add(new("APACHE_VARIABLE", "A configuration variable is unresolved; the affected path is not inferred.", VerificationStatus.Unsupported, source)); return null; }
            return value;
        }
        string? Resolve(string value, string source)
        {
            var expanded = Expand(value, source); if (expanded is null) return null;
            try { return DiscoverySafety.FullPath(Path.IsPathFullyQualified(expanded) ? expanded : Path.Combine(serverRoot, expanded)); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { findings.Add(new("APACHE_LOCAL_PATH", "A configured path is not a supported local path.", VerificationStatus.Unsupported, source)); return null; }
        }
        void Read(string path, int depth, bool optional = false)
        {
            if (cancellationToken.IsCancellationRequested) return;
            if (depth > 8 || files.Count >= 64 || clock.Elapsed > TimeSpan.FromSeconds(4)) { findings.Add(new("APACHE_LIMIT", "Bounded Apache include inspection reached its limit.", VerificationStatus.NotTested, path)); return; }
            if (!DiscoverySafety.Approved(path, roots)) { findings.Add(new("APACHE_INCLUDE_APPROVAL", "An Apache include is outside the selected scopes and was not read.", VerificationStatus.NeedsApproval, path)); return; }
            if (active.Contains(path)) { findings.Add(new("APACHE_INCLUDE_CYCLE", "An Apache include cycle was skipped.", VerificationStatus.Unsupported, path)); return; }
            if (!visited.Add(path)) return;
            if (optional && !File.Exists(path)) return;
            try
            {
                var text = DiscoverySafety.ReadText(path, 256 * 1024); bytes += Encoding.UTF8.GetByteCount(text);
                if (bytes > 2 * 1024 * 1024) { findings.Add(new("APACHE_BYTE_LIMIT", "Apache include data exceeded the total byte limit.", VerificationStatus.NotTested, path)); return; }
                files.Add(path); active.Add(path);
                var lines = text.Split('\n');
                for (var lineNumber = 0; lineNumber < Math.Min(lines.Length, 5000); lineNumber++)
                {
                    if (cancellationToken.IsCancellationRequested || clock.Elapsed > TimeSpan.FromSeconds(4)) break;
                    var words = SplitLine(lines[lineNumber]); if (words.Count == 0) continue;
                    var name = words[0].ToLowerInvariant();
                    if (name == "<virtualhost")
                    {
                        stack.Push(current);
                        current = new Context { Configuration = path, DocumentRoot = global.DocumentRoot, Host = global.Host, Https = global.Https };
                        foreach (var address in words.Skip(1)) if (ParsePort(address.TrimEnd('>')) is int port) current.Ports.Add(port);
                        continue;
                    }
                    if (name == "</virtualhost>") { if (stack.Count > 0) { contexts.Add(current); current = stack.Pop(); } else findings.Add(new("APACHE_CONTEXT", "Unbalanced virtual-host context.", VerificationStatus.Unsupported, path)); continue; }
                    if (words.Count < 2) continue;
                    if (name == "define" && words.Count == 3) { variables[words[1]] = words[2]; continue; }
                    if (name == "serverroot") { var resolved = Resolve(words[1], path); if (resolved is not null) serverRoot = resolved; continue; }
                    if (name is "include" or "includeoptional")
                    {
                        var include = Resolve(words[1], path); if (include is null) continue;
                        if (include.IndexOfAny(['*','?']) >= 0)
                        {
                            var directory = Path.GetDirectoryName(include)!; var pattern = Path.GetFileName(include);
                            if (directory.IndexOfAny(['*','?']) >= 0 || !DiscoverySafety.Approved(directory, roots) || DiscoverySafety.HasReparsePoint(directory)) { findings.Add(new("APACHE_GLOB_SCOPE", "Only bounded filename globs within an approved local directory are supported.", VerificationStatus.NeedsApproval, path)); continue; }
                            if (Directory.Exists(directory)) foreach (var child in Directory.EnumerateFiles(directory, pattern).Take(65)) Read(child, depth + 1, name == "includeoptional");
                        }
                        else Read(include, depth + 1, name == "includeoptional");
                        continue;
                    }
                    if (name == "listen") { if (ParsePort(words[1]) is int port) global.Ports.Add(port); continue; }
                    if (name == "documentroot") { var resolved = Resolve(words[1], path); if (resolved is not null) current.DocumentRoot = resolved; continue; }
                    if (name == "servername")
                    {
                        var raw = words[1]; var value = Expand(raw, path); if (value is null) continue;
                        if (Uri.TryCreate("http://" + value.TrimEnd('/') + "/", UriKind.Absolute, out var uri) && string.IsNullOrEmpty(uri.UserInfo)) { current.Host = uri.Host; if (!uri.IsDefaultPort) current.Ports.Add(uri.Port); }
                        continue;
                    }
                    if (name == "sslengine") { current.Https = words[1].Equals("on", StringComparison.OrdinalIgnoreCase); continue; }
                    if (name == "alias" && words.Count == 3 && words[1].StartsWith('/'))
                    {
                        var target = Resolve(words[2], path); if (target is not null) current.Aliases.Add((words[1], target));
                    }
                }
                active.Remove(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or RegexMatchTimeoutException or FormatException)
            { active.Remove(path); findings.Add(DiscoverySafety.Error("APACHE_READ_FAILED", path)); }
        }
        Read(initial, 0);
        if (stack.Count > 0) findings.Add(new("APACHE_CONTEXT", "An unfinished virtual-host context was not published.", VerificationStatus.Unsupported, initial));
        contexts.Insert(0, global);
        foreach (var context in contexts)
        {
            var ports = context.Ports.Count > 0 ? context.Ports : global.Ports;
            if (ports.Count == 0) { findings.Add(new("APACHE_PORT_UNKNOWN", "No explicit listener or virtual-host port was resolved; no port was assumed.", VerificationStatus.NotTested, context.Configuration)); continue; }
            foreach (var port in ports.Distinct())
            {
                if (!string.IsNullOrWhiteSpace(context.DocumentRoot)) sites.Add(new(context.Configuration, context.DocumentRoot, context.Host, port, context.Https));
                foreach (var alias in context.Aliases) sites.Add(new(context.Configuration, context.DocumentRoot, context.Host, port, context.Https, alias.Alias, alias.Target));
            }
        }
        findings.Add(new("APACHE_STATIC_ONLY", "Apache directives were read statically. Module/conditional activation, reachability and effective running configuration were not tested.", VerificationStatus.Configured, initial));
        if (cancellationToken.IsCancellationRequested) findings.Add(new("APACHE_CANCELLED", "Apache inspection was cancelled.", VerificationStatus.NotTested));
        return new(sites.Distinct().ToArray(), findings, files);
    }

    public static string? LocalUrl(ApacheSite site, string? relativePath = null)
    {
        var host = site.Host.Contains(':') ? "[" + site.Host.Trim('[',']') + "]" : site.Host;
        var prefix = site.Alias ?? "/";
        var suffix = relativePath is null ? "" : string.Join('/', relativePath.Replace('\\','/').Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Uri.EscapeDataString));
        return DiscoverySafety.LocalUrl($"{(site.Https ? "https" : "http")}://{host}:{site.Port}/{prefix.Trim('/')}/{suffix}".Replace($":{site.Port}//", $":{site.Port}/"));
    }

    private static int? ParsePort(string address)
    {
        var colon = address.LastIndexOf(':'); var value = colon >= 0 ? address[(colon + 1)..] : address;
        return int.TryParse(value, out var port) && port is > 0 and <= 65535 ? port : null;
    }

    private static List<string> SplitLine(string line)
    {
        var words = new List<string>(); var current = new StringBuilder(); var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"') { quoted = !quoted; continue; }
            if (!quoted && c == '#') break;
            if (c == '\\' && i + 1 < line.Length && line[i + 1] == '"') { current.Append('"'); i++; continue; }
            if (!quoted && char.IsWhiteSpace(c)) { if (current.Length > 0) { words.Add(current.ToString()); current.Clear(); } }
            else current.Append(c);
        }
        if (quoted) throw new FormatException("Unclosed Apache quote.");
        if (current.Length > 0) words.Add(current.ToString());
        return words;
    }
}
