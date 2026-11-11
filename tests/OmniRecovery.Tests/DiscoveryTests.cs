using System.Text.Json;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Discovery;

namespace OmniRecovery.Tests;

public static class DiscoveryTests
{
    public static void Register(TestSuite t)
    {
        t.Add("Discovery: Joomla markers/version distinguish a site from configuration names", async () =>
        {
            using var fixture = Fixture.Create(t); var real = fixture.Directory("htdocs/real"); Joomla(real, "5.4.2");
            fixture.Write("htdocs/not-joomla/configuration.php", Config());
            var result = await new JoomlaDiscovery().ScanAsync(new() { Roots = [fixture.Root], MaxDepth = 6 }, null, CancellationToken.None);
            t.Equal(1, result.Installations.Count); t.Equal("5.4.2", result.Installations[0].Version); t.Equal(real, result.Installations[0].RootPath);
            t.True(result.Installations[0].Status == VerificationStatus.Discovered); t.True(result.Installations[0].PublicUrl is null);
        });
        t.Add("Discovery: modern PHP version constants are read without execution", async () =>
        {
            using var fixture = Fixture.Create(t); var site = fixture.Directory("site"); Joomla(site, null);
            fixture.Write("site/libraries/src/Version.php", "<?php namespace Joomla\\CMS; final class Version { const MAJOR_VERSION=4; const MINOR_VERSION=4; const PATCH_VERSION=11; }");
            var result = await new JoomlaDiscovery().ScanAsync(new() { Roots = [fixture.Root], MaxDepth = 3 }, null, CancellationToken.None);
            t.Equal("4.4.11", result.Installations.Single().Version);
        });
        t.Add("Discovery: depth/file budgets report partial coverage", async () =>
        {
            using var fixture = Fixture.Create(t); Joomla(fixture.Directory("a/b/c"), "5.3.0"); fixture.Write("first.txt", "x"); fixture.Write("second.txt", "x");
            var depth = await new JoomlaDiscovery().ScanAsync(new() { Roots = [fixture.Root], MaxDepth = 1 }, null, CancellationToken.None);
            t.Equal(0, depth.Installations.Count); t.True(!depth.Complete);
            var budget = await new JoomlaDiscovery().ScanAsync(new() { Roots = [fixture.Root], MaxFiles = 1 }, null, CancellationToken.None);
            t.True(budget.FilesVisited <= 1); t.True(!budget.Complete);
        });
        t.Add("Discovery: cancellation preserves a noncomplete result and progress", async () =>
        {
            using var fixture = Fixture.Create(t); using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
            var progress = new ImmediateProgress();
            var result = await new JoomlaDiscovery().ScanAsync(new() { Roots = [fixture.Root] }, progress, cancellation.Token);
            t.True(result.Cancelled); t.True(!result.Complete); t.Equal(0, result.DirectoriesVisited); t.True(progress.Events.Count > 0);
        });
        t.Add("Discovery: excluded dependency folders are not traversed", async () =>
        {
            using var fixture = Fixture.Create(t); Joomla(fixture.Directory("node_modules/hidden"), "5.3.1");
            var result = await new JoomlaDiscovery().ScanAsync(new() { Roots = [fixture.Root] }, null, CancellationToken.None);
            t.Equal(0, result.Installations.Count); t.Equal(1, result.DirectoriesVisited);
        });
        t.Add("Discovery: UNC scopes are rejected without probing network hosts", async () =>
        {
            var result = await new JoomlaDiscovery().ScanAsync(new() { Roots = [@"\\unrequested-host\share"] }, null, CancellationToken.None);
            t.Equal(0, result.DirectoriesVisited); t.True(!result.Complete); t.True(result.Findings.Any(f => f.Code == "ROOT_INVALID"));
        });
        t.Add("Configuration: static literals/comments do not leak secrets into evidence", () =>
        {
            using var fixture = Fixture.Create(t);
            var path = fixture.Write("configuration.php", "<?php /* public $password = 'decoy'; */ class JConfig { public $dbtype='mysqli'; public $host='localhost:3307'; public $user='fixture_user'; public $password='fixture-only-secret'; public $db='fixture_db'; public $dbprefix='j5_'; public $live_site='http://localhost/example'; }");
            var result = new StaticConfigurationResolver().Resolve(path, [fixture.Root]);
            t.Equal(VerificationStatus.Configured, result.Status); t.Equal("mysql", result.Connection!.Engine); t.Equal(3307u, result.Connection.Port); t.Equal("localhost", result.Connection.Host);
            t.True(result.Connection.Password == "fixture-only-secret", "Literal secret should be kept only in memory.");
            t.Equal("http://localhost/example/", result.LiveSite);
            var json = JsonSerializer.Serialize(result); t.True(!json.Contains("fixture-only-secret")); t.True(!result.ToString().Contains("fixture-only-secret"));
        });
        t.Add("Configuration: only explicitly named environment variables are requested", () =>
        {
            using var fixture = Fixture.Create(t); var requested = new List<string>();
            var path = fixture.Write("configuration.php", Config("getenv('OMNI_FIXTURE_SECRET')"));
            var resolver = new StaticConfigurationResolver(name => { requested.Add(name); return name == "OMNI_FIXTURE_SECRET" ? "synthetic-env-value" : null; });
            var result = resolver.Resolve(path, [fixture.Root]); t.Equal(VerificationStatus.Configured, result.Status); t.Equal(1, requested.Count); t.Equal("OMNI_FIXTURE_SECRET", requested[0]);
            t.True(result.Connection!.Password == "synthetic-env-value", "Explicit environment value is retained in the private connection only.");
        });
        t.Add("Configuration: missing/dynamic environment references remain unresolved", () =>
        {
            using var fixture = Fixture.Create(t); var path = fixture.Write("configuration.php", Config("getenv('OMNI_MISSING')"));
            var result = new StaticConfigurationResolver(_ => null).Resolve(path, [fixture.Root]);
            t.True(result.Connection is null); t.True(result.UnresolvedFields.Contains("password"));
            fixture.Write("configuration.php", Config("getenv($untrusted)"));
            var dynamic = new StaticConfigurationResolver(_ => throw new Exception("Must not enumerate or resolve a dynamic name.")).Resolve(path, [fixture.Root]); t.True(dynamic.Connection is null);
        });
        t.Add("Configuration: anchored static loader chains resolve within scope", () =>
        {
            using var fixture = Fixture.Create(t); var path = fixture.Write("configuration.php", "<?php require_once __DIR__ . '/private/loader.php';");
            fixture.Write("private/loader.php", "<?php require(dirname(__FILE__) . '/settings.php');"); fixture.Write("private/settings.php", Config());
            var result = new StaticConfigurationResolver().Resolve(path, [fixture.Root]);
            t.Equal(VerificationStatus.Configured, result.Status); t.Equal(3, result.ReferenceChain.Count); t.True(result.EffectivePath!.EndsWith("settings.php"));
        });
        t.Add("Configuration: external loader waits for exact approval and scope boundary", () =>
        {
            using var fixture = Fixture.Create(t); var site = fixture.Directory("site"); var outside = fixture.Write("site-other/private.php", Config());
            var path = fixture.Write("site/configuration.php", "<?php require __DIR__ . '/../site-other/private.php';");
            var resolver = new StaticConfigurationResolver(); var pending = resolver.Resolve(path, [site]);
            t.Equal(VerificationStatus.NeedsApproval, pending.Status); t.True(pending.Connection is null); t.Equal(outside, pending.PendingApprovalPaths.Single()); t.Equal(1, pending.ReferenceChain.Count);
            var approved = resolver.Resolve(path, [site], [outside]); t.Equal(VerificationStatus.Configured, approved.Status);
        });
        t.Add("Configuration: dynamic/interpolated/duplicate assignments fail closed", () =>
        {
            using var fixture = Fixture.Create(t); var resolver = new StaticConfigurationResolver();
            foreach (var source in new[] { Config("file_get_contents('/unapproved')"), Config("\"$interpolated\""), Config().Replace("public $host='localhost';", "public $host='localhost'; public $host='elsewhere';"), Config() + " $override = true;" })
            {
                var path = fixture.Write("configuration.php", source); var result = resolver.Resolve(path, [fixture.Root]); t.True(result.Connection is null, "Ambiguous source must not produce connection settings.");
            }
        });
        t.Add("Configuration: constructor/conditional loaders are never interpreted", () =>
        {
            using var fixture = Fixture.Create(t); var resolver = new StaticConfigurationResolver();
            var constructor = Config().Replace("class JConfig {", "class JConfig { public function __construct() { $this->host='different'; }");
            var path = fixture.Write("configuration.php", constructor); t.True(resolver.Resolve(path, [fixture.Root]).Connection is null);
            fixture.Write("private.php", Config()); fixture.Write("configuration.php", "<?php if (getenv('MODE')) { require __DIR__ . '/private.php'; }");
            var conditional = resolver.Resolve(path, [fixture.Root]); t.True(conditional.Connection is null); t.Equal(1, conditional.ReferenceChain.Count);
        });
        t.Add("Configuration: cycles/oversized input remain bounded", () =>
        {
            using var fixture = Fixture.Create(t); var path = fixture.Write("configuration.php", "<?php require __DIR__ . '/loop.php';"); fixture.Write("loop.php", "<?php require __DIR__ . '/configuration.php';");
            var resolver = new StaticConfigurationResolver(); var cycle = resolver.Resolve(path, [fixture.Root]); t.True(cycle.Connection is null); t.True(cycle.Findings.Any(f => f.Code == "CONFIG_CYCLE"));
            fixture.Write("configuration.php", new string(' ', 270000) + Config()); var large = resolver.Resolve(path, [fixture.Root]); t.True(large.Connection is null); t.True(large.Findings.Any(f => f.Status == VerificationStatus.Error));
        });
        t.Add("Configuration: IPv6/port and local URL policy are explicit", () =>
        {
            using var fixture = Fixture.Create(t); var path = fixture.Write("configuration.php", Config().Replace("'localhost'", "'[::1]:3308'").Replace("public $dbprefix='j_';", "public $dbprefix='j_'; public $live_site='https://example.invalid/';"));
            var result = new StaticConfigurationResolver().Resolve(path, [fixture.Root]); t.Equal("::1", result.Connection!.Host); t.Equal(3308u, result.Connection.Port); t.True(result.LiveSite is null); t.True(!result.Connection.AllowRemote);
        });
        t.Add("Apache: bounded includes/vhosts/aliases produce declared local URLs", () =>
        {
            using var fixture = Fixture.Create(t); var root = fixture.Root.Replace('\\','/');
            var path = fixture.Write("httpd.conf", $"Define SRVROOT \"{root}\"\nServerRoot \"${{SRVROOT}}\"\nListen 8080\nServerName localhost:8080\nDocumentRoot \"${{SRVROOT}}/htdocs\"\nInclude conf/*.conf\n");
            fixture.Write("conf/extra.conf", $"# Include untrusted.conf\nAlias /phpmyadmin \"{root}/phpMyAdmin\"\n<VirtualHost 127.0.0.1:8443>\nServerName localhost\nSSLEngine on\nDocumentRoot \"{root}/secure\"\n</VirtualHost>\n");
            var parsed = new ApacheConfigurationParser().Parse(path, [fixture.Root]); t.Equal(2, parsed.FilesRead.Count);
            var alias = parsed.Sites.Single(s => s.Alias == "/phpmyadmin"); t.Equal("http://localhost:8080/phpmyadmin/", ApacheConfigurationParser.LocalUrl(alias));
            t.True(parsed.Sites.Any(s => s.Port == 8443 && s.Https && s.DocumentRoot.EndsWith("secure")));
        });
        t.Add("Apache: outside includes and unresolved variables are not read", () =>
        {
            using var fixture = Fixture.Create(t); var scope = fixture.Directory("approved"); fixture.Write("outside.conf", "Listen 9999\nDocumentRoot /not-approved\n");
            var path = fixture.Write("approved/httpd.conf", "Listen 8081\nInclude ../outside.conf\nInclude ${UNKNOWN}/hidden.conf\n");
            var parsed = new ApacheConfigurationParser().Parse(path, [scope]); t.Equal(1, parsed.FilesRead.Count); t.True(parsed.Findings.Any(f => f.Status == VerificationStatus.NeedsApproval)); t.True(parsed.Findings.Any(f => f.Code == "APACHE_VARIABLE")); t.True(parsed.Sites.All(s => s.Port != 9999));
        });
        t.Add("Apache: cycles, cancellation and remote URLs fail safely", () =>
        {
            using var fixture = Fixture.Create(t); var path = fixture.Write("httpd.conf", "Include httpd.conf\nListen 80\nDocumentRoot htdocs\n");
            var parsed = new ApacheConfigurationParser().Parse(path, [fixture.Root]); t.True(parsed.Findings.Any(f => f.Code == "APACHE_INCLUDE_CYCLE"));
            using var cancellation = new CancellationTokenSource(); cancellation.Cancel(); var cancelled = new ApacheConfigurationParser().Parse(path, [fixture.Root], cancellation.Token); t.Equal(0, cancelled.FilesRead.Count);
            t.True(ApacheConfigurationParser.LocalUrl(new(path, fixture.Root, "example.invalid", 80, false)) is null);
            t.True(ApacheConfigurationParser.LocalUrl(new(path, fixture.Root, "user:pass@localhost", 80, false)) is null);
        });
        t.Add("Discovery: XML external entities are prohibited", async () =>
        {
            using var fixture = Fixture.Create(t); var site = fixture.Directory("site"); Joomla(site, "5.1.0");
            fixture.Write("site/administrator/manifests/files/joomla.xml", "<!DOCTYPE extension [<!ENTITY x SYSTEM 'file:///not-read'>]><extension><name>files_joomla</name><version>&x;</version></extension>");
            var result = await new JoomlaDiscovery().ScanAsync(new() { Roots = [site], MaxDepth = 0 }, null, CancellationToken.None);
            t.Equal("UNKNOWN", result.Installations.Single().Version); t.True(result.Installations.Single().Findings.Any(f => f.Code == "JOOMLA_VERSION_READ_FAILED"));
        });
        t.Add("Configuration: PHP property case, octal integers and conflicting ports are not guessed", () =>
        {
            using var fixture = Fixture.Create(t); var resolver = new StaticConfigurationResolver();
            foreach (var source in new[] { Config().Replace("$host=", "$Host="), Config().Replace("public $dbprefix='j_';", "public $dbprefix='j_'; public $port=03306;"), Config().Replace("'localhost'", "'localhost:3307'").Replace("public $dbprefix='j_';", "public $dbprefix='j_'; public $port=3308;") })
            { var path = fixture.Write("configuration.php", source); t.True(resolver.Resolve(path, [fixture.Root]).Connection is null); }
            var valid = fixture.Write("configuration.php", Config().Replace("'localhost'", "'localhost:3307'").Replace("public $dbprefix='j_';", "public $dbprefix='j_'; public $port=3307;"));
            var resolved = resolver.Resolve(valid, [fixture.Root]); t.Equal(VerificationStatus.Configured, resolved.Status); t.Equal("localhost", resolved.Connection!.Host); t.Equal(3307u, resolved.Connection.Port);
        });
        t.Add("Discovery: queued directories are bounded as well as visited directories", async () =>
        {
            using var fixture = Fixture.Create(t); for (var i = 0; i < 30; i++) fixture.Directory("child" + i);
            var result = await new JoomlaDiscovery().ScanAsync(new() { Roots = [fixture.Root], MaxDirectories = 3 }, null, CancellationToken.None);
            t.True(result.DirectoriesVisited <= 3); t.True(!result.Complete); t.True(result.Findings.Any(f => f.Code == "SCAN_QUEUE_LIMIT"));
        });
        t.Add("Discovery/configuration: reparse directories are not traversed", async () =>
        {
            using var fixture = Fixture.Create(t); var selected = fixture.Directory("selected"); var target = fixture.Directory("outside"); Joomla(target, "5.4.0");
            var link = Path.Combine(selected, "linked"); Directory.CreateSymbolicLink(link, target);
            var scan = await new JoomlaDiscovery().ScanAsync(new() { Roots = [selected] }, null, CancellationToken.None);
            t.Equal(0, scan.Installations.Count); t.True(scan.Findings.Any(f => f.Code == "ENTRY_REPARSE"));
            var config = new StaticConfigurationResolver().Resolve(Path.Combine(link, "configuration.php"), [selected]); t.True(config.Connection is null); t.Equal(VerificationStatus.Error, config.Status);
        });
    }

    private static string Config(string passwordExpression = "'synthetic-only'") => "<?php class JConfig { public $dbtype='mysqli'; public $host='localhost'; public $user='fixture_user'; public $password=" + passwordExpression + "; public $db='fixture_db'; public $dbprefix='j_'; }";
    private static void Joomla(string root, string? version)
    {
        Directory.CreateDirectory(Path.Combine(root, "includes")); Directory.CreateDirectory(Path.Combine(root, "administrator")); Directory.CreateDirectory(Path.Combine(root, "libraries", "src"));
        File.WriteAllText(Path.Combine(root, "includes", "defines.php"), "<?php defined('_JEXEC') or die;"); File.WriteAllText(Path.Combine(root, "includes", "framework.php"), "<?php // fixture marker only");
        File.WriteAllText(Path.Combine(root, "configuration.php"), Config());
        if (version is not null) { var path = Path.Combine(root, "administrator", "manifests", "files"); Directory.CreateDirectory(path); File.WriteAllText(Path.Combine(path, "joomla.xml"), $"<extension><name>files_joomla</name><version>{version}</version></extension>"); }
    }
    private sealed class ImmediateProgress : IProgress<ScanProgress> { public List<ScanProgress> Events { get; } = []; public void Report(ScanProgress value) => Events.Add(value); }
    private sealed class Fixture : IDisposable
    {
        public string Root { get; }
        private Fixture(string root) => Root = root;
        public static Fixture Create(TestSuite t)
        {
            var workspace = new DirectoryInfo(AppContext.BaseDirectory);
            while (workspace is not null && !File.Exists(Path.Combine(workspace.FullName, "Directory.Build.props"))) workspace = workspace.Parent;
            if (workspace is null) throw new InvalidOperationException("Workspace boundary unavailable.");
            var allowed = Path.Combine(workspace.FullName, ".local", "tests"); var selected = Path.GetFullPath(t.Root);
            if (!selected.Equals(allowed, StringComparison.OrdinalIgnoreCase) && !selected.StartsWith(allowed + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Discovery fixture root must be inside the workspace .local/tests directory.");
            return new(t.NewDirectory("discovery"));
        }
        public string Directory(string relative) { var path = Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar)); System.IO.Directory.CreateDirectory(path); return path; }
        public string Write(string relative, string text) { var path = Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar)); System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, text); return path; }
        public void Dispose()
        {
            var full = Path.GetFullPath(Root); var parent = Path.GetDirectoryName(full)!;
            if (!Path.GetFileName(full).StartsWith("discovery-", StringComparison.Ordinal) || !full.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Invalid fixture cleanup boundary.");
            if (System.IO.Directory.Exists(full)) System.IO.Directory.Delete(full, true);
        }
    }
}
