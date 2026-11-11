using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Discovery;

public sealed class JoomlaDiscovery : IJoomlaDiscovery
{
    public Task<ScanResult> ScanAsync(ScanOptions options, IProgress<ScanProgress>? progress, CancellationToken cancellationToken) =>
        Task.Run(() => Scan(options, progress, cancellationToken), CancellationToken.None);

    private static ScanResult Scan(ScanOptions options, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var started = DateTimeOffset.UtcNow; var watch = Stopwatch.StartNew();
        var findings = new List<Finding>(); var installations = new List<JoomlaInstallation>();
        var dirs = 0; var files = 0; var complete = true;
        var maxDepth = Math.Clamp(options.MaxDepth, 0, 20); var maxFiles = Math.Clamp(options.MaxFiles, 1, 200000);
        var maxDirectories = Math.Clamp(options.MaxDirectories, 1, 50000); var maxSeconds = Math.Clamp(options.MaxSeconds, 1, 300);
        var excluded = new HashSet<string>(options.ExcludedDirectories, StringComparer.OrdinalIgnoreCase);
        var roots = new List<string>();
        if (options.Roots.Count > 64) { complete = false; findings.Add(new("ROOT_LIMIT", "Only the first 64 explicit roots are inspected.", VerificationStatus.NotTested)); }
        foreach (var root in options.Roots.Take(64))
        {
            if (cancellationToken.IsCancellationRequested || watch.Elapsed.TotalSeconds >= maxSeconds) { complete = false; break; }
            try
            {
                var path = DiscoverySafety.FullPath(root);
                if (DiscoverySafety.HasReparsePoint(path)) { findings.Add(new("ROOT_REPARSE", "A selected root crosses a reparse point and was skipped.", VerificationStatus.Unsupported, path)); complete = false; continue; }
                if (!Directory.Exists(path)) { findings.Add(new("ROOT_MISSING", "A selected root is unavailable.", VerificationStatus.Unavailable, path)); complete = false; continue; }
                if (!roots.Contains(path, StringComparer.OrdinalIgnoreCase)) roots.Add(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            { findings.Add(new("ROOT_INVALID", "A root could not be inspected as a local directory.", VerificationStatus.Error)); complete = false; }
        }
        if (roots.Count == 0 && !cancellationToken.IsCancellationRequested) { complete = false; findings.Add(new("ROOT_NONE", "No accessible local scan root was selected.", VerificationStatus.Unavailable)); }
        var queue = new Queue<(string Path, int Depth)>(); foreach (var root in roots.Take(maxDirectories)) queue.Enqueue((root, 0));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var users = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", "Users");
        bool Limited() => files >= maxFiles || dirs >= maxDirectories || watch.Elapsed.TotalSeconds >= maxSeconds;
        void Report(string path, string message) { try { progress?.Report(new(dirs, files, installations.Count, path, message)); } catch { /* Observer failures cannot invalidate a read-only scan. */ } }
        while (queue.Count > 0)
        {
            if (cancellationToken.IsCancellationRequested) { complete = false; break; }
            if (Limited()) { complete = false; findings.Add(new("SCAN_LIMIT", "A configured directory, file or time limit was reached; coverage is incomplete.", VerificationStatus.NotTested)); break; }
            var item = queue.Dequeue(); if (!seen.Add(item.Path)) continue;
            try
            {
                if (DiscoverySafety.HasReparsePoint(item.Path)) { findings.Add(new("DIRECTORY_REPARSE", "A reparse-point path was skipped.", VerificationStatus.NotTested, item.Path)); continue; }
                dirs++;
                var installation = Detect(item.Path);
                if (installation is not null) installations.Add(installation);
                Report(item.Path, "Inspecting bounded local directory metadata.");
                foreach (var entry in Directory.EnumerateFileSystemEntries(item.Path))
                {
                    if (cancellationToken.IsCancellationRequested || Limited()) { complete = false; break; }
                    var attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) { findings.Add(new("ENTRY_REPARSE", "A reparse-point entry was skipped.", VerificationStatus.NotTested, entry)); continue; }
                    if ((attributes & FileAttributes.Directory) == 0) { files++; continue; }
                    if (item.Depth >= maxDepth) { complete = false; continue; }
                    if (excluded.Contains(Path.GetFileName(entry))) continue;
                    // Personal profiles require explicit selection; a whole-volume scope does not imply permission.
                    if (DiscoverySafety.Within(entry, users) && !roots.Any(r => DiscoverySafety.Within(r, users) && DiscoverySafety.Within(entry, r))) continue;
                    if (dirs + queue.Count >= maxDirectories) { complete = false; if (!findings.Any(f => f.Code == "SCAN_QUEUE_LIMIT")) findings.Add(new("SCAN_QUEUE_LIMIT", "The directory queue reached the configured bound; additional subtrees were skipped.", VerificationStatus.NotTested)); break; }
                    queue.Enqueue((entry, item.Depth + 1));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            { complete = false; findings.Add(DiscoverySafety.Error("DIRECTORY_READ_FAILED", item.Path)); }
        }
        if (!cancellationToken.IsCancellationRequested && watch.Elapsed.TotalSeconds < maxSeconds)
        {
            var configs = roots.Select(r => Path.Combine(r, "apache", "conf", "httpd.conf")).Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var config in configs)
            {
                if (watch.Elapsed.TotalSeconds >= maxSeconds || cancellationToken.IsCancellationRequested) { complete = false; break; }
                using var time = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                time.CancelAfter(TimeSpan.FromSeconds(Math.Max(.01, maxSeconds - watch.Elapsed.TotalSeconds)));
                var apache = new ApacheConfigurationParser().Parse(config, roots, time.Token);
                findings.AddRange(apache.Findings);
                foreach (var installation in installations)
                {
                    foreach (var site in apache.Sites)
                    {
                        var directory = site.AliasTarget ?? site.DocumentRoot;
                        if (!string.IsNullOrEmpty(directory) && DiscoverySafety.Within(installation.RootPath, directory))
                        {
                            var relative = Path.GetRelativePath(directory, installation.RootPath);
                            var url = ApacheConfigurationParser.LocalUrl(site, relative == "." ? "" : relative);
                            if (url is null) continue;
                            installation.PublicUrl = url; installation.AdministratorUrl = url + "administrator/"; installation.ApacheConfiguration = site.ConfigurationPath;
                            installation.Findings.Add(new("JOOMLA_URL_DECLARED", "Loopback URL derived from static Apache directives; reachability and active virtual-host selection are not tested.", VerificationStatus.Configured, site.ConfigurationPath)); break;
                        }
                    }
                }
            }
        }
        if (!complete && !findings.Any(f => f.Code == "SCAN_LIMIT") && !cancellationToken.IsCancellationRequested) findings.Add(new("SCAN_PARTIAL", "One or more depth bounds, access failures or inspection limits left incomplete coverage.", VerificationStatus.NotTested));
        if (cancellationToken.IsCancellationRequested) findings.Add(new("SCAN_CANCELLED", "Discovery was cancelled; partial observations are retained.", VerificationStatus.NotTested));
        Report("", cancellationToken.IsCancellationRequested ? "Cancelled." : complete ? "Completed within selected scope." : "Completed with incomplete coverage.");
        return new(installations.DistinctBy(x => x.Id).ToArray(), findings, dirs, files, complete && !cancellationToken.IsCancellationRequested, cancellationToken.IsCancellationRequested, started, DateTimeOffset.UtcNow);
    }

    private static JoomlaInstallation? Detect(string root)
    {
        var manifest = Path.Combine(root, "administrator", "manifests", "files", "joomla.xml");
        var defines = Path.Combine(root, "includes", "defines.php");
        var framework = Path.Combine(root, "includes", "framework.php");
        var versionFiles = new[] { "libraries/src/Version.php", "libraries/cms/version/version.php", "libraries/joomla/version.php" }.Select(p => Path.Combine(root, p.Replace('/', Path.DirectorySeparatorChar))).ToArray();
        bool SafeFile(string path) => File.Exists(path) && !DiscoverySafety.HasReparsePoint(path);
        var versionFile = versionFiles.FirstOrDefault(SafeFile);
        // A filename configuration.php alone is never sufficient proof of a Joomla installation.
        if (!SafeFile(defines) || !SafeFile(framework) || (!SafeFile(manifest) && versionFile is null) || !Directory.Exists(Path.Combine(root, "administrator"))) return null;
        var item = new JoomlaInstallation { Id = StableIdentity.For(root), Name = Path.GetFileName(root), RootPath = root, ConfigurationPath = Path.Combine(root, "configuration.php") };
        item.Findings.Add(new("JOOMLA_MARKERS", "Joomla administrator/version metadata and includes/defines.php + includes/framework.php markers are present.", VerificationStatus.Discovered, root));
        try
        {
            if (SafeFile(manifest))
            {
                var content = DiscoverySafety.ReadText(manifest, 128 * 1024);
                using var reader = XmlReader.Create(new StringReader(content), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 128 * 1024 });
                var document = XDocument.Load(reader);
                var name = document.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "name")?.Value ?? "";
                var version = document.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "version")?.Value.Trim();
                if (name.Contains("Joomla", StringComparison.OrdinalIgnoreCase) && ValidVersion(version)) item.Version = version!;
            }
            if (item.Version == "UNKNOWN" && versionFile is not null)
            {
                var tokens = PhpStaticReader.Tokenize(DiscoverySafety.ReadText(versionFile, 128 * 1024));
                var values = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
                for (var i = 0; i + 2 < tokens.Count; i++)
                    if (tokens[i + 1].Text == "=" && tokens[i + 2].Kind is "string" or "number" && !tokens[i + 2].Dynamic)
                        values[tokens[i].Text.TrimStart('$')] = tokens[i + 2].Text;
                if (values.TryGetValue("MAJOR_VERSION", out var major) && values.TryGetValue("MINOR_VERSION", out var minor) && values.TryGetValue("PATCH_VERSION", out var patch))
                { var version = major + "." + minor + "." + patch; if (ValidVersion(version)) item.Version = version; }
                else if (values.TryGetValue("RELEASE", out var release) && values.TryGetValue("DEV_LEVEL", out var level) && ValidVersion(release + "." + level)) item.Version = release + "." + level;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or XmlException or FormatException or ArgumentException)
        { item.Findings.Add(DiscoverySafety.Error("JOOMLA_VERSION_READ_FAILED", root)); }
        if (!File.Exists(item.ConfigurationPath)) item.Findings.Add(new("JOOMLA_CONFIG_MISSING", "The Joomla markers are present but configuration.php is unavailable; installation completeness is not assumed.", VerificationStatus.Unavailable, item.ConfigurationPath));
        if (item.Version == "UNKNOWN") item.Findings.Add(new("JOOMLA_VERSION_UNKNOWN", "No unambiguous static Joomla version could be established.", VerificationStatus.NotTested, root));
        return item;
    }

    private static bool ValidVersion(string? value) => value is not null && Regex.IsMatch(value, @"^\d{1,2}\.\d{1,3}(\.\d{1,4})?([.\-+][A-Za-z0-9.\-]+)?$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
}
