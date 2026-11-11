using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using MySqlConnector;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Database;
using OmniRecovery.Infrastructure.Discovery;
using OmniRecovery.Infrastructure.Recovery;

namespace OmniRecovery.Tests;

/// <summary>Opt-in tests for a freshly initialized, disposable loopback server under this workspace's .local directory.</summary>
public static class MariaDbIntegrationTests
{
    private const string Reason = "Isolated synthetic integration fixture; no real Joomla site is involved.";
    private const string Password = "Synthetic-Recovered-57!";
    public static void RegisterPhp(TestSuite suite, string phpPath)
    {
        if (string.IsNullOrWhiteSpace(phpPath) || !Path.IsPathFullyQualified(phpPath) || phpPath.StartsWith(@"\\") || phpPath.StartsWith("//"))
            throw new ArgumentException("PHP interoperability requires an explicitly selected absolute local executable path.");
        var php = Path.GetFullPath(phpPath);
        suite.Add("PHP verifies generated Joomla bcrypt over stdin without disclosing secrets", async () =>
        {
            if (!File.Exists(php)) throw new InvalidOperationException("Explicit PHP interoperability executable is unavailable; test not verified.");
            const string password = "Synthetic-🔒-Interoperability-57!";
            var hash = new BCryptPasswordHasher().Hash(password);
            const string code = "$v=json_decode(stream_get_contents(STDIN),true); if(!is_array($v)||!password_verify($v['password'],$v['hash'])){exit(2);} echo 'PHP_BCRYPT_VERIFIED';";
            var start = new ProcessStartInfo(php) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add("-n"); start.ArgumentList.Add("-r"); start.ArgumentList.Add(code);
            using var process = Process.Start(start) ?? throw new InvalidOperationException("PHP fixture could not start.");
            var output = process.StandardOutput.ReadToEndAsync(); var errors = process.StandardError.ReadToEndAsync();
            await process.StandardInput.WriteAsync(JsonSerializer.Serialize(new { password, hash })); process.StandardInput.Close();
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); }
            catch (TimeoutException) { try { process.Kill(true); } catch (InvalidOperationException) { } throw new InvalidOperationException("PHP fixture exceeded its deadline."); }
            var text = await output; _ = await errors;
            suite.Equal(0, process.ExitCode, "PHP did not verify the synthetic hash."); suite.Equal("PHP_BCRYPT_VERIFIED", text, "Unexpected PHP fixture response (content withheld).");
        });
    }
    public static void Register(TestSuite suite, int port)
    {
        if (port is < 1024 or > 65535 || port == 3306) throw new ArgumentException("Integration requires an explicitly selected nondefault disposable server port.");
        Fixture? fixture = null;
        Fixture F() => fixture ?? throw new InvalidOperationException("Disposable fixture preflight did not complete.");
        suite.Add("MariaDB integration preflight and two isolated synthetic schemas", async () =>
        {
            fixture = await Fixture.Create(port);
            suite.True(fixture.First.Database != fixture.Second.Database);
        });
        suite.Add("MariaDB selected-schema inspection and parameterized SQL workbench", async () =>
        {
            var f = F(); var repository = new MySqlAccountRepository();
            var result = await repository.InspectAsync(f.First, default);
            suite.Equal(VerificationStatus.Verified, result.Status); suite.Equal(2, result.Accounts.Count);
            suite.True(result.Accounts.Single(x => x.Id == 1).AdministratorPrivileges.Contains("grant detected"));
            suite.True(result.Findings.Any(x => x.Code == "ASSET_INHERITANCE"));
            var plan = SqlIntelligence.CreatePlan("SELECT id, username FROM x9_users WHERE username='fixture_admin' LIMIT 2", f.First);
            var rows = await repository.ExecuteReadOnlyAsync(f.First, plan, default); suite.Equal(1, rows.Rows.Count);
            var injection = SqlIntelligence.CreatePlan("SELECT id FROM x9_users WHERE username='x'' OR 1=1'", f.First);
            suite.Equal(0, (await repository.ExecuteReadOnlyAsync(f.First, injection, default)).Rows.Count);
            suite.False(JsonSerializer.Serialize(result).Contains(f.InitialHash));
        });
        suite.Add("MariaDB direct fallback confirms one row and preserves other schema and controls", async () =>
        {
            var f = F(); var service = new RecoveryService(new MySqlAccountRepository());
            var p = await service.PreviewAsync(Installation(f.First), f.First, 1, true, fallbackReason: Reason);
            await suite.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(f.First, p, "RESET other", Password, true));
            var outcome = await service.ExecuteAsync(f.First, p, p.ConfirmationText, Password, true);
            suite.True(outcome.Success, "Disposable MariaDB transaction did not succeed."); suite.Equal(1, outcome.AffectedRows); suite.True(outcome.RecordVerified);
            suite.True(new BCryptPasswordHasher().Verify(Password, await f.Value(f.First, "SELECT password FROM x9_users WHERE id=1")));
            suite.Equal(f.InitialHash, await f.Value(f.First, "SELECT password FROM x9_users WHERE id=2"), "Other user was changed.");
            suite.Equal(f.InitialHash, await f.Value(f.Second, "SELECT password FROM x9_users WHERE id=1"), "Other database was changed.");
            suite.Equal("1", await f.Value(f.First, "SELECT block FROM x9_users WHERE id=1")); suite.Equal("1", await f.Value(f.First, "SELECT requireReset FROM x9_users WHERE id=1"));
            suite.Equal("fixture-mfa", await f.Value(f.First, "SELECT marker FROM x9_fixture_mfa")); suite.Equal("fixture-session", await f.Value(f.First, "SELECT marker FROM x9_fixture_session"));
        });
        suite.Add("MariaDB optimistic identity and selected database binding refuse stale previews", async () =>
        {
            var f = F(); var repository = new MySqlAccountRepository(); var service = new RecoveryService(repository);
            var p = await service.PreviewAsync(Installation(f.First), f.First, 1, true, fallbackReason: Reason);
            await f.Execute(f.First, "UPDATE x9_users SET password=@hash WHERE id=1", new Dictionary<string,object?> { ["@hash"] = f.InitialHash });
            var outcome = await service.ExecuteAsync(f.First, p, p.ConfirmationText, Password, true); suite.False(outcome.Success); suite.Equal(0, outcome.AffectedRows);
            suite.Equal(f.InitialHash, await f.Value(f.First, "SELECT password FROM x9_users WHERE id=1"));
            p = await service.PreviewAsync(Installation(f.First), f.First, 1, true, fallbackReason: Reason);
            await suite.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(f.Second, p, p.ConfirmationText, Password, true));
            var wrong = f.First.Copy(); wrong.Prefix = "wrong_";
            var inspection = await repository.InspectAsync(wrong, default); suite.Equal(0, inspection.Accounts.Count);
            await suite.ThrowsAsync<InvalidOperationException>(() => service.PreviewAsync(Installation(wrong), wrong, 1, true, fallbackReason: Reason));
        });
        suite.Add("MariaDB trigger-bearing users tables refuse direct fallback", async () =>
        {
            var f = F();
            await f.Execute(f.First, "CREATE TRIGGER x9_fixture_guard BEFORE UPDATE ON x9_users FOR EACH ROW SET NEW.block=NEW.block");
            var service = new RecoveryService(new MySqlAccountRepository());
            await suite.ThrowsAsync<InvalidOperationException>(() => service.PreviewAsync(Installation(f.First), f.First, 1, true, fallbackReason: Reason));
            suite.Equal(f.InitialHash, await f.Value(f.First, "SELECT password FROM x9_users WHERE id=1"));
        });
        suite.Add("MariaDB unreachable selected endpoint returns a bounded unavailable result", async () =>
        {
            var c = F().First.Copy(); c.Port = 1;
            var result = await new MySqlAccountRepository().InspectAsync(c, default);
            suite.Equal(VerificationStatus.Unavailable, result.Status); suite.Equal(0, result.Accounts.Count);
            suite.False(JsonSerializer.Serialize(result).Contains("Password="));
        });
        suite.Add("MariaDB discovery through external static configuration to confirmed recovery", async () =>
        {
            var f = await Fixture.Create(port);
            var parent = suite.NewDirectory("mariadb-loader-chain");
            var site = Path.Combine(parent, "public"); var configuration = Path.Combine(site, "configuration.php");
            foreach (var relative in new[] { "includes", "administrator/manifests/files", "libraries/src" })
                Directory.CreateDirectory(Path.Combine(site, relative));
            Directory.CreateDirectory(Path.Combine(parent, "private-config"));
            await File.WriteAllTextAsync(Path.Combine(site, "includes", "defines.php"), "<?php defined('_JEXEC') or die;");
            await File.WriteAllTextAsync(Path.Combine(site, "includes", "framework.php"), "<?php // synthetic discovery marker only");
            await File.WriteAllTextAsync(Path.Combine(site, "administrator", "manifests", "files", "joomla.xml"), "<extension><name>files_joomla</name><version>5.4.8</version></extension>");
            await File.WriteAllTextAsync(configuration, "<?php require_once __DIR__ . '/../private-config/configuration.php';");
            await File.WriteAllTextAsync(Path.Combine(parent, "private-config", "configuration.php"),
                "<?php class JConfig { public $dbtype='mysqli'; public $host='127.0.0.1:" + port.ToString(CultureInfo.InvariantCulture)
                + "'; public $user='root'; public $password=''; public $db='" + SqlIntelligence.ValidateIdentifier(f.First.Database) + "'; public $dbprefix='x9_'; }");
            var discovery = await new JoomlaDiscovery().ScanAsync(new() { Roots = [parent], MaxDepth = 6 }, null, default);
            var installation = discovery.Installations.Single(x => string.Equals(x.RootPath, site, StringComparison.OrdinalIgnoreCase));
            suite.Equal("5.4.8", installation.Version);
            var resolved = new StaticConfigurationResolver().Resolve(installation.ConfigurationPath!, [parent]);
            suite.Equal(VerificationStatus.Configured, resolved.Status); suite.Equal(2, resolved.ReferenceChain.Count);
            installation.Configuration = resolved;
            var connection = resolved.Connection ?? throw new InvalidOperationException("Synthetic external configuration did not resolve.");
            suite.Equal(f.First.Database, connection.Database); suite.Equal((uint)port, connection.Port); suite.Equal("x9_", connection.Prefix);
            var repository = new MySqlAccountRepository(); var inspection = await repository.InspectAsync(connection, default);
            suite.Equal(VerificationStatus.Verified, inspection.Status); suite.Equal(2, inspection.Accounts.Count);
            var service = new RecoveryService(repository);
            var preview = await service.PreviewAsync(installation, connection, inspection.Accounts.Single(x => x.Id == 1).Id, true, fallbackReason: Reason);
            var outcome = await service.ExecuteAsync(connection, preview, preview.ConfirmationText, Password, true);
            suite.True(outcome.Success, "Continuous synthetic discovery/configuration/recovery path failed.");
            suite.Equal(1, outcome.AffectedRows); suite.True(outcome.RecordVerified);
            suite.True(new BCryptPasswordHasher().Verify(Password, await f.Value(f.First, "SELECT password FROM x9_users WHERE id=1")));
            suite.Equal(f.InitialHash, await f.Value(f.First, "SELECT password FROM x9_users WHERE id=2"), "Other user was changed by continuous recovery.");
            suite.Equal(f.InitialHash, await f.Value(f.Second, "SELECT password FROM x9_users WHERE id=1"), "Other database was changed by continuous recovery.");
            suite.Equal("1", await f.Value(f.First, "SELECT block FROM x9_users WHERE id=1")); suite.Equal("1", await f.Value(f.First, "SELECT requireReset FROM x9_users WHERE id=1"));
        });
    }
    private static JoomlaInstallation Installation(ConnectionSettings connection) => new() { Id = "isolated-mariadb-fixture", Name = "Disposable MariaDB integration", Version = "5.4.0", Configuration = new() { Status = VerificationStatus.Configured, Connection = connection.Copy() } };
    private sealed class Fixture(int port, string first, string second, string initialHash)
    {
        public string InitialHash { get; } = initialHash;
        public ConnectionSettings First { get; } = Settings(port, first);
        public ConnectionSettings Second { get; } = Settings(port, second);
        private static ConnectionSettings Settings(int p, string db) => new() { Engine = "mysql", Host = "127.0.0.1", Port = (uint)p, Database = db, Username = "root", Password = "", Prefix = "x9_" };
        private static MySqlConnection Open(int p, string db = "") => new(new MySqlConnectionStringBuilder { Server = "127.0.0.1", Port = (uint)p, UserID = "root", Password = "", Database = db, Pooling = false, ConnectionTimeout = 3, DefaultCommandTimeout = 10, AllowLoadLocalInfile = false, SslMode = MySqlSslMode.None }.ConnectionString);
        public async Task Execute(ConnectionSettings c, string sql, IReadOnlyDictionary<string,object?>? parameters = null)
        {
            await using var db = Open((int)c.Port, c.Database); await db.OpenAsync(); await using var command = db.CreateCommand(); command.CommandText = sql;
            if (parameters is not null) foreach (var value in parameters) command.Parameters.AddWithValue(value.Key, value.Value);
            await command.ExecuteNonQueryAsync();
        }
        public async Task<string> Value(ConnectionSettings c, string sql)
        {
            await using var db = Open((int)c.Port, c.Database); await db.OpenAsync(); await using var command = db.CreateCommand(); command.CommandText = sql;
            return Convert.ToString(await command.ExecuteScalarAsync(), CultureInfo.InvariantCulture) ?? "";
        }
        public static async Task<Fixture> Create(int port)
        {
            await using var server = Open(port); await server.OpenAsync();
            await using (var check = server.CreateCommand())
            {
                check.CommandText = "SELECT @@port,@@datadir"; await using var reader = await check.ExecuteReaderAsync();
                if (!await reader.ReadAsync() || Convert.ToInt32(reader.GetValue(0)) != port) throw new InvalidOperationException("Disposable server port identity mismatch.");
                var data = Path.GetFullPath(reader.GetString(1));
                var allowed = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, ".local")) + Path.DirectorySeparatorChar;
                if (!data.StartsWith(allowed, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Server datadir is outside the disposable workspace boundary; no fixture writes permitted.");
            }
            await using (var check = server.CreateCommand())
            {
                check.CommandText = "SHOW DATABASES"; await using var reader = await check.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var name = reader.GetString(0);
                    if (name is not ("information_schema" or "mysql" or "performance_schema" or "sys" or "test") && !name.StartsWith("omni_fixture_", StringComparison.Ordinal))
                        throw new InvalidOperationException("Server contains an unexpected nonfixture database; no fixture writes permitted.");
                }
            }
            var token = Guid.NewGuid().ToString("N"); var f = new Fixture(port, "omni_fixture_a_" + token, "omni_fixture_b_" + token, new BCryptPasswordHasher().Hash("Synthetic-initial-fixture-57!"));
            foreach (var c in new[] { f.First, f.Second })
            {
                await using (var create = server.CreateCommand()) { create.CommandText = "CREATE DATABASE `" + SqlIntelligence.ValidateIdentifier(c.Database) + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"; await create.ExecuteNonQueryAsync(); }
                await f.Execute(c, """
                    CREATE TABLE x9_users(id BIGINT PRIMARY KEY,username VARCHAR(150) NOT NULL,name VARCHAR(255),email VARCHAR(255),password VARCHAR(100),block TINYINT NOT NULL,requireReset TINYINT NOT NULL,lastvisitDate DATETIME NULL) ENGINE=InnoDB;
                    CREATE TABLE x9_user_usergroup_map(user_id BIGINT,group_id BIGINT,PRIMARY KEY(user_id,group_id)) ENGINE=InnoDB;
                    CREATE TABLE x9_usergroups(id BIGINT PRIMARY KEY,parent_id BIGINT,title VARCHAR(100),lft INT,rgt INT) ENGINE=InnoDB;
                    CREATE TABLE x9_assets(id BIGINT PRIMARY KEY,parent_id BIGINT,name VARCHAR(100),rules TEXT) ENGINE=InnoDB;
                    CREATE TABLE x9_fixture_mfa(marker VARCHAR(100)) ENGINE=InnoDB;
                    CREATE TABLE x9_fixture_session(marker VARCHAR(100)) ENGINE=InnoDB;
                    INSERT INTO x9_users VALUES(1,'fixture_admin','Synthetic Admin','fixture@example.invalid',@hash,1,1,NULL),(2,'other_user','Other User','other@example.invalid',@hash,0,0,NULL);
                    INSERT INTO x9_usergroups VALUES(1,0,'Public',1,8),(21,1,'Privileged fixture group',2,7),(22,21,'Inherited administrators',3,4);
                    INSERT INTO x9_user_usergroup_map VALUES(1,22),(2,1);
                    INSERT INTO x9_assets VALUES(1,0,'root.1','{"core.admin":{"21":true}}'),(2,1,'com_users','{}');
                    INSERT INTO x9_fixture_mfa VALUES('fixture-mfa'); INSERT INTO x9_fixture_session VALUES('fixture-session');
                    """, new Dictionary<string,object?> { ["@hash"] = f.InitialHash });
            }
            return f;
        }
    }
}
