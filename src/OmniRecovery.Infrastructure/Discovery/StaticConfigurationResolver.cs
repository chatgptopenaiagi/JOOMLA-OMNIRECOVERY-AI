using System.Diagnostics;
using System.Globalization;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Discovery;

public sealed class StaticConfigurationResolver : IConfigurationResolver
{
    private readonly Func<string, string?> environment;
    public StaticConfigurationResolver() : this(Environment.GetEnvironmentVariable) { }
    public StaticConfigurationResolver(Func<string, string?> environmentReader) => environment = environmentReader ?? throw new ArgumentNullException(nameof(environmentReader));

    public ConfigurationResolution Resolve(string configurationPath, IReadOnlyCollection<string> approvedRoots, IReadOnlyCollection<string>? explicitlyApprovedFiles = null)
    {
        var result = new ConfigurationResolution { Status = VerificationStatus.NotTested };
        var properties = new Dictionary<string, PhpValue>(StringComparer.Ordinal);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var active = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var clock = Stopwatch.StartNew(); var ambiguous = false; var classes = 0; var totalBytes = 0L;
        string[] roots, files; string initial;
        try
        {
            roots = approvedRoots.Select(DiscoverySafety.FullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            files = (explicitlyApprovedFiles ?? []).Select(DiscoverySafety.FullPath).ToArray();
            initial = DiscoverySafety.FullPath(configurationPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        { result.Status = VerificationStatus.Error; result.Findings.Add(new("CONFIG_PATH_INVALID", "A selected configuration scope is not a supported local path.", VerificationStatus.Error)); return result; }

        void Read(string path, int depth)
        {
            if (depth > 8 || visited.Count >= 16 || clock.Elapsed > TimeSpan.FromSeconds(3)) { ambiguous = true; result.Findings.Add(new("CONFIG_LIMIT", "Static loader inspection reached its bounded limit.", VerificationStatus.Unsupported, path)); return; }
            if (!DiscoverySafety.Approved(path, roots, files))
            { if (!result.PendingApprovalPaths.Contains(path, StringComparer.OrdinalIgnoreCase)) result.PendingApprovalPaths.Add(path); return; }
            if (active.Contains(path)) { ambiguous = true; result.Findings.Add(new("CONFIG_CYCLE", "The loader reference chain contains a cycle.", VerificationStatus.Unsupported, path)); return; }
            if (!visited.Add(path)) return;
            try
            {
                if (DiscoverySafety.HasReparsePoint(path)) throw new IOException();
                var info = new FileInfo(path); totalBytes += info.Length;
                if (totalBytes > 2 * 1024 * 1024) throw new IOException();
                var text = DiscoverySafety.ReadText(path, 256 * 1024);
                result.ReferenceChain.Add(path); active.Add(path);
                var document = PhpStaticReader.Parse(text, path, environment);
                ambiguous |= document.Ambiguous;
                if (document.HasConfigurationClass) { classes++; result.EffectivePath = path; }
                foreach (var property in document.Properties)
                {
                    if (!properties.TryAdd(property.Key, property.Value)) { properties[property.Key] = new(false, ""); ambiguous = true; }
                }
                foreach (var expression in document.Includes)
                {
                    var value = PhpStaticReader.Evaluate(expression, path, environment, false);
                    if (!value.Resolved || string.IsNullOrWhiteSpace(value.Text))
                    { ambiguous = true; result.Findings.Add(new("CONFIG_DYNAMIC_LOADER", "A loader expression cannot be resolved without executing PHP.", VerificationStatus.Unsupported, path)); continue; }
                    // Relative paths without an explicit __DIR__/__FILE__ anchor depend on PHP's working/include path.
                    if (!Path.IsPathFullyQualified(value.Text))
                    { ambiguous = true; result.Findings.Add(new("CONFIG_RELATIVE_LOADER", "A working-directory-dependent loader path is unresolved; use an explicit approved file selection.", VerificationStatus.Unsupported, path)); continue; }
                    Read(DiscoverySafety.FullPath(value.Text), depth + 1);
                }
                active.Remove(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or FormatException or NotSupportedException)
            { active.Remove(path); ambiguous = true; result.Findings.Add(DiscoverySafety.Error("CONFIG_READ_OR_PARSE_FAILED", path)); }
        }
        Read(initial, 0);
        var required = new[] { "dbtype", "host", "user", "password", "db", "dbprefix" };
        foreach (var name in required) if (!properties.TryGetValue(name, out var value) || !value.Resolved) result.UnresolvedFields.Add(name);
        if (classes != 1) { ambiguous = true; result.Findings.Add(new("CONFIG_CLASS_COUNT", "Exactly one statically resolvable JConfig class is required.", VerificationStatus.Unsupported, initial)); }
        if (properties.TryGetValue("live_site", out var live) && live.Resolved && live.Text.Length > 0)
        {
            result.LiveSite = DiscoverySafety.LocalUrl(live.Text);
            if (result.LiveSite is null) result.Findings.Add(new("LIVE_SITE_NOT_LOCAL", "The configured site URL is not an approved credential-free loopback HTTP URL.", VerificationStatus.NotTested, result.EffectivePath));
        }
        if (result.PendingApprovalPaths.Count > 0) { result.Status = VerificationStatus.NeedsApproval; result.Findings.Add(new("CONFIG_SCOPE_APPROVAL", "A loader references files outside the selected scopes. Review and explicitly approve those paths before resolving credentials.", VerificationStatus.NeedsApproval)); return result; }
        if (ambiguous || result.UnresolvedFields.Count > 0)
        { result.Status = result.Findings.Any(f => f.Status == VerificationStatus.Error) ? VerificationStatus.Error : VerificationStatus.Unsupported; result.Findings.Add(new("CONFIG_UNRESOLVED", "Dynamic, ambiguous or incomplete configuration remains unresolved; no connection settings were inferred.", result.Status, initial)); return result; }

        string Get(string key) => properties[key].Text;
        var engine = Get("dbtype").ToLowerInvariant();
        engine = engine is "mysqli" or "pdomysql" ? "mysql" : engine;
        var host = Get("host"); uint port = 3306; var explicitPort = properties.ContainsKey("port"); uint? inlinePort = null;
        if (properties.TryGetValue("port", out var portValue))
        {
            if (!portValue.Resolved || !uint.TryParse(portValue.Text, NumberStyles.None, CultureInfo.InvariantCulture, out port) || port is < 1 or > 65535)
            { result.Status = VerificationStatus.Unsupported; result.UnresolvedFields.Add("port"); return result; }
        }
        if (host.StartsWith('['))
        {
            var end = host.IndexOf(']');
            uint parsed = 0;
            if (end < 0 || (end + 1 < host.Length && (host[end + 1] != ':' || !uint.TryParse(host[(end + 2)..], out parsed) || parsed is < 1 or > 65535)))
            { result.Status = VerificationStatus.Unsupported; result.UnresolvedFields.Add("host"); return result; }
            if (end + 1 < host.Length) inlinePort = parsed;
            host = host[1..end];
        }
        else if (host.Count(c => c == ':') == 1)
        {
            var colon = host.LastIndexOf(':');
            if (!uint.TryParse(host[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed is < 1 or > 65535)
            { result.Status = VerificationStatus.Unsupported; result.UnresolvedFields.Add("host"); return result; }
            inlinePort = parsed; host = host[..colon];
        }
        if (inlinePort is not null)
        {
            if (explicitPort && port != inlinePort.Value) { result.Status = VerificationStatus.Unsupported; result.UnresolvedFields.Add("conflicting_port"); return result; }
            port = inlinePort.Value;
        }
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(Get("db")) || string.IsNullOrWhiteSpace(Get("user")) || Get("dbprefix").Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '_')) || Get("dbprefix").Length is < 1 or > 64)
        { result.Status = VerificationStatus.Unsupported; result.Findings.Add(new("CONFIG_VALUES_INVALID", "Required connection identifiers are empty or outside supported bounds.", VerificationStatus.Unsupported, result.EffectivePath)); return result; }
        result.Connection = new ConnectionSettings { Engine = engine, Host = host, Port = port, Database = Get("db"), Username = Get("user"), Password = Get("password"), Prefix = Get("dbprefix"), AllowRemote = false };
        result.Status = VerificationStatus.Configured;
        result.Findings.Add(new("CONFIG_STATIC_RESOLVED", "Connection settings resolved statically. Authentication and database access have not been tested; secret values are excluded from evidence.", VerificationStatus.Configured, result.EffectivePath));
        return result;
    }
}
