using Microsoft.Data.Sqlite;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Database;
using OmniRecovery.Infrastructure.Recovery;

namespace OmniRecovery.Tests;

public static class DatabaseTests
{
    private const string Password = "Synthetic-Password-42!";
    private const string Reason = "Synthetic fixture: supported recovery intentionally unavailable.";
    private static readonly Lazy<string> InitialHash = new(() => new BCryptPasswordHasher().Hash("Initial-fixture-only-42!"));
    public static void Register(TestSuite suite)
    {
        suite.Add("SQL allowlist rejects injection, secrets, functions and extra statements", () =>
        {
            var c = MySql();
            foreach (var sql in new[] {
                "SELECT password FROM jos_users", "SELECT * FROM jos_users", "SELECT id FROM jos_users; DROP TABLE jos_users",
                "SELECT SLEEP(5) FROM jos_users", "SELECT id FROM jos_users INTO OUTFILE 'file'", "SELECT id FROM jos_users UNION SELECT id FROM other_users",
                "SELECT id FROM jos_users -- comment", "SELECT id FROM jos_users /* comment */", "SELECT id FROM other_users",
                "SELECT id FROM db.jos_users", "SELECT id FROM jos_users WHERE id=(SELECT id FROM jos_users)",
                "SELECT id FROM jos_users LIMIT 201", "SELECT id FROM jos_users WHERE id=1 OR id=2", "SELECT id FROM jos_users WHERE username='a\\b'" })
                suite.Throws<ArgumentException>(() => SqlIntelligence.CreatePlan(sql, c));
            var plan = SqlIntelligence.CreatePlan("SELECT id, username FROM jos_users WHERE username='x'' OR 1=1' AND id>=1 ORDER BY id DESC LIMIT 12", c);
            suite.True(plan.ReadOnly); suite.Equal("x' OR 1=1", (string)plan.Parameters["@p0"]!);
            suite.False(plan.Sql.Contains("OR 1=1")); suite.Equal("joomla", plan.Database);
        });
        suite.Add("Database hosts require exact loopback or explicit remote opt-in", () =>
        {
            foreach (var host in new[] { "localhost", "127.0.0.1", "::1" }) { var c = MySql(); c.Host = host; SqlIntelligence.ValidateConnectionTarget(c); }
            foreach (var host in new[] { "localhost.evil.test", "127.0.0.1.evil.test", "database.example.test" }) { var c = MySql(); c.Host = host; suite.Throws<InvalidOperationException>(() => SqlIntelligence.ValidateConnectionTarget(c)); }
            var injection = MySql(); injection.Host = "localhost;AllowLoadLocalInfile=true"; suite.Throws<ArgumentException>(() => SqlIntelligence.ValidateConnectionTarget(injection));
            var remote = MySql(); remote.Host = "database.example.test"; remote.AllowRemote = true; SqlIntelligence.ValidateConnectionTarget(remote);
            suite.Throws<ArgumentException>(() => SqlIntelligence.ValidateIdentifier("jos_users` SET password='x'"));
        });
        suite.Add("bcrypt uses modern PHP revision and rejects truncation", () =>
        {
            var hasher = new BCryptPasswordHasher(); var hash = hasher.Hash(Password);
            suite.True(hash.StartsWith("$2y$12$", StringComparison.Ordinal)); suite.Equal(60, hash.Length); suite.True(hasher.Verify(Password, hash)); suite.False(hasher.Verify("Incorrect-fixture-42!", hash));
            suite.Throws<ArgumentException>(() => hasher.Hash(new string('a', 73)));
            suite.Throws<ArgumentException>(() => hasher.Hash(string.Concat(Enumerable.Repeat("😀", 19))));
            suite.Throws<ArgumentException>(() => hasher.Hash("TwelveCharacters\0secret"));
            suite.Throws<ArgumentException>(() => hasher.Hash("MalformedUnicode" + '\ud800'));
            var generated = Enumerable.Range(0, 20).Select(_ => hasher.GeneratePassword()).ToArray();
            suite.True(generated.All(x => x.Length == 24 && x.All(char.IsAscii))); suite.Equal(20, generated.Distinct().Count());
        });
        suite.Add("SQLite inspection uses group and root asset inheritance, never group8 alone", async () =>
        {
            var f = await Fixture.Create(suite); var repo = new SqliteAccountRepository();
            var inspected = await repo.InspectAsync(f.Connection, default); suite.Equal(VerificationStatus.Verified, inspected.Status);
            suite.True(inspected.Accounts.Single(x => x.Id == 1).AdministratorPrivileges.Contains("grant detected"));
            suite.True(inspected.Accounts.Single(x => x.Id == 1).Groups.Contains("Child administrators"));
            await f.Sql("UPDATE jos_assets SET rules='{}'");
            inspected = await repo.InspectAsync(f.Connection, default);
            suite.True(inspected.Accounts.Single(x => x.Id == 1).AdministratorPrivileges.Contains("not established"));
            suite.True(inspected.Findings.Any(x => x.Code == "SQLITE_NOT_PRODUCTION"));
            suite.False(System.Text.Json.JsonSerializer.Serialize(inspected).Contains(InitialHash.Value));
            await f.Sql("INSERT INTO jos_assets VALUES(2,999,'com_fixture','{}')");
            inspected = await repo.InspectAsync(f.Connection, default);
            suite.True(inspected.Findings.Any(x => x.Code == "ASSET_INHERITANCE" && x.Status == VerificationStatus.NotTested));
            suite.True(inspected.Accounts.Single(x => x.Id == 1).AdministratorPrivileges.StartsWith("Unknown"));
        });
        suite.Add("Wrong prefix is reported without account fallback", async () =>
        {
            var f = await Fixture.Create(suite); var c = f.Connection.Copy(); c.Prefix = "wrong_";
            var repository = new SqliteAccountRepository(true); var inspected = await repository.InspectAsync(c, default);
            suite.Equal(0, inspected.Accounts.Count); suite.True(inspected.Findings.Any(x => x.Code == "PREFIX_CANDIDATES"));
            var service = new RecoveryService(repository);
            await suite.ThrowsAsync<InvalidOperationException>(() => service.PreviewAsync(Installation(c), c, 1, true, fallbackReason: Reason));
            suite.Equal(InitialHash.Value, await f.Value("SELECT password FROM jos_users WHERE id=1"));
        });
        suite.Add("Joomla numeric ACL grants, denies and malformed values remain distinct", async () =>
        {
            var f = await Fixture.Create(suite); var repository = new SqliteAccountRepository();
            foreach (var permission in new[] { "true", "1" })
            {
                await f.SetRules("{\"core.admin\":{\"8\":" + permission + "}}");
                var result = await repository.InspectAsync(f.Connection, default);
                suite.True(result.Accounts.Single(x => x.Id == 1).AdministratorPrivileges.Contains("grant detected"));
            }
            foreach (var permission in new[] { "false", "0" })
            {
                await f.SetRules("{\"core.admin\":{\"8\":" + permission + "}}");
                var result = await repository.InspectAsync(f.Connection, default);
                suite.True(result.Accounts.Single(x => x.Id == 1).AdministratorPrivileges.Contains("deny evidence"));
            }
            foreach (var permission in new[] { "2", "-1", "1.5", "\"1\"", "null" })
            {
                await f.SetRules("{\"core.admin\":{\"8\":" + permission + "}}");
                var result = await repository.InspectAsync(f.Connection, default);
                suite.True(result.Accounts.Single(x => x.Id == 1).AdministratorPrivileges.StartsWith("Unknown"));
            }
            await f.SetRules("{\"core.admin\":{\"8\":1,\"9\":0}}");
            var conflict = await repository.InspectAsync(f.Connection, default);
            suite.True(conflict.Accounts.Single(x => x.Id == 1).AdministratorPrivileges.StartsWith("Conflicting"));
        });
        suite.Add("Generic SQLite is inspectable without claiming Joomla support", async () =>
        {
            var path = Path.Combine(suite.NewDirectory("generic-sqlite"), "generic.sqlite");
            await using (var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ConnectionString)) { await db.OpenAsync(); await using var cmd = db.CreateCommand(); cmd.CommandText = "CREATE TABLE notes(id INTEGER PRIMARY KEY, note TEXT)"; await cmd.ExecuteNonQueryAsync(); }
            var c = new ConnectionSettings { Engine = "sqlite", SqlitePath = path, Database = "generic", Prefix = "jos_" };
            var result = await new SqliteAccountRepository().InspectAsync(c, default);
            suite.Equal(VerificationStatus.Accessible, result.Status); suite.True(result.Tables.Contains("notes")); suite.Equal(0, result.Accounts.Count);
        });
        suite.Add("Query executor reparses forged plans and keeps values parameterized", async () =>
        {
            var f = await Fixture.Create(suite); var repo = new SqliteAccountRepository();
            var plan = SqlIntelligence.CreatePlan("SELECT id, username FROM jos_users WHERE username='x'' OR 1=1' LIMIT 5", f.Connection);
            suite.Equal(0, (await repo.ExecuteReadOnlyAsync(f.Connection, plan, default)).Rows.Count);
            var forged = new QueryPlan("forged", f.Connection.Database, ["jos_users"], "SELECT password FROM jos_users", true, new Dictionary<string, object?>());
            await suite.ThrowsAsync<ArgumentException>(() => repo.ExecuteReadOnlyAsync(f.Connection, forged, default));
            var wrongDatabase = SqlIntelligence.AccountListPlan(f.Connection) with { Database = "different" };
            await suite.ThrowsAsync<ArgumentException>(() => repo.ExecuteReadOnlyAsync(f.Connection, wrongDatabase, default));
            var valid = await repo.ExecuteReadOnlyAsync(f.Connection, SqlIntelligence.AccountListPlan(f.Connection), default);
            suite.Equal(2, valid.Rows.Count); suite.False(valid.Columns.Contains("password"));
        });
        suite.Add("SQL quoted identifiers round-trip without changing quoted text values", async () =>
        {
            var f = await Fixture.Create(suite); var repo = new SqliteAccountRepository();
            var generated = SqlIntelligence.AccountListPlan(f.Connection);
            var roundTrip = SqlIntelligence.CreatePlan(generated.Sql, f.Connection);
            suite.Equal(2, (await repo.ExecuteReadOnlyAsync(f.Connection, roundTrip, default)).Rows.Count);
            await f.Sql("UPDATE jos_users SET username='fixture`literal' WHERE id=1");
            var text = SqlIntelligence.CreatePlan("SELECT `id` FROM `jos_users` WHERE `username`='fixture`literal'", f.Connection);
            suite.Equal("fixture`literal", (string)text.Parameters["@p0"]!);
            suite.Equal(1, (await repo.ExecuteReadOnlyAsync(f.Connection, text, default)).Rows.Count);
            foreach (var invalid in new[] { "SELECT `password` FROM `jos_users`", "SELECT `id;DROP` FROM jos_users", "SELECT id FROM `jos_users` UNION SELECT id FROM jos_users", "SELECT id FROM `jos_users" })
                suite.Throws<ArgumentException>(() => SqlIntelligence.CreatePlan(invalid, f.Connection));
        });
        suite.Add("Recovery version evidence cannot be borrowed for a manual or different target", async () =>
        {
            var first = await Fixture.Create(suite); var second = await Fixture.Create(suite);
            var repository = new SqliteAccountRepository(true); var service = new RecoveryService(repository);
            var bound = Installation(first.Connection);
            var manual = new JoomlaInstallation { Id = "manual", Name = "Unresolved fixture", Version = "5.4.8" };
            await suite.ThrowsAsync<InvalidOperationException>(() => service.PreviewAsync(manual, first.Connection, 1, true, fallbackReason: Reason));
            await suite.ThrowsAsync<InvalidOperationException>(() => service.PreviewAsync(bound, second.Connection, 1, true, fallbackReason: Reason));
            await suite.ThrowsAsync<InvalidOperationException>(() => repository.CreateRecoveryPreviewAsync(bound, second.Connection, 1, default));
            var selected = MySql(); var installation = Installation(selected);
            foreach (var change in new Action<ConnectionSettings>[] { c => c.Database = "another", c => c.Host = "127.0.0.1", c => c.Port = 3307, c => c.Prefix = "x9_", c => c.Engine = "sqlite" })
            {
                var other = selected.Copy(); change(other);
                suite.Throws<InvalidOperationException>(() => RecoveryService.RequireTargetBinding(installation, other));
            }
            foreach (var alias in new[] { "mysql", "mysqli", "mariadb" })
            {
                var credentials = selected.Copy(); credentials.Engine = alias; credentials.Host = "LOCALHOST";
                credentials.Username = "different_authorized_operator"; credentials.Password = "synthetic-credential-override";
                RecoveryService.RequireTargetBinding(installation, credentials);
            }
            suite.Equal(InitialHash.Value, await first.Value("SELECT password FROM jos_users WHERE id=1"));
            suite.Equal(InitialHash.Value, await second.Value("SELECT password FROM jos_users WHERE id=1"));
        });
        suite.Add("Production SQLite and unsupported Joomla recovery are refused", async () =>
        {
            var f = await Fixture.Create(suite); var disabled = new RecoveryService(new SqliteAccountRepository());
            await suite.ThrowsAsync<NotSupportedException>(() => disabled.PreviewAsync(Installation(f.Connection), f.Connection, 1, true, fallbackReason: Reason));
            var service = new RecoveryService(new SqliteAccountRepository(true));
            foreach (var version in new[] { "UNKNOWN", "3.10.12", "6.0.0", "5.x", "5.0.0 or 6" })
            { var install = Installation(f.Connection); install.Version = version; await suite.ThrowsAsync<NotSupportedException>(() => service.PreviewAsync(install, f.Connection, 1, true, fallbackReason: Reason)); }
            await suite.ThrowsAsync<InvalidOperationException>(() => service.PreviewAsync(Installation(f.Connection), f.Connection, 1, false, fallbackReason: Reason));
            await suite.ThrowsAsync<ArgumentException>(() => service.PreviewAsync(Installation(f.Connection), f.Connection, 1, true));
        });
        suite.Add("Recovery requires exact confirmation and unchanged preview", async () =>
        {
            var f = await Fixture.Create(suite); var service = new RecoveryService(new SqliteAccountRepository(true));
            var p = await service.PreviewAsync(Installation(f.Connection), f.Connection, 1, true, fallbackReason: Reason);
            await suite.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(f.Connection, p, p.ConfirmationText.ToLowerInvariant(), Password, true));
            await suite.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(f.Connection, p with { Username = "other" }, p.ConfirmationText, Password, true));
            await suite.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(f.Connection, p, p.ConfirmationText, Password, false));
            suite.Equal(InitialHash.Value, await f.Value("SELECT password FROM jos_users WHERE id=1"));
        });
        suite.Add("Synthetic recovery changes exactly one password and preserves controls", async () =>
        {
            var f = await Fixture.Create(suite); var service = new RecoveryService(new SqliteAccountRepository(true));
            var p = await service.PreviewAsync(Installation(f.Connection), f.Connection, 1, true, fallbackReason: Reason);
            var outcome = await service.ExecuteAsync(f.Connection, p, p.ConfirmationText, Password, true);
            suite.True(outcome.Success); suite.Equal(1, outcome.AffectedRows); suite.True(outcome.RecordVerified);
            suite.True(new BCryptPasswordHasher().Verify(Password, await f.Value("SELECT password FROM jos_users WHERE id=1")));
            suite.Equal(InitialHash.Value, await f.Value("SELECT password FROM jos_users WHERE id=2"));
            suite.Equal("1", await f.Value("SELECT block FROM jos_users WHERE id=1")); suite.Equal("1", await f.Value("SELECT requireReset FROM jos_users WHERE id=1"));
            suite.Equal("fixture-mfa-unchanged", await f.Value("SELECT marker FROM fixture_mfa"));
            await suite.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(f.Connection, p, p.ConfirmationText, Password, true));
        });
        suite.Add("Changed account identity or optimistic password refuses recovery", async () =>
        {
            foreach (var mutation in new[] { "UPDATE jos_users SET username='renamed' WHERE id=1", "UPDATE jos_users SET password='external-change' WHERE id=1" })
            {
                var f = await Fixture.Create(suite); var service = new RecoveryService(new SqliteAccountRepository(true));
                var p = await service.PreviewAsync(Installation(f.Connection), f.Connection, 1, true, fallbackReason: Reason);
                await f.Sql(mutation); var before = await f.Value("SELECT password FROM jos_users WHERE id=1");
                var result = await service.ExecuteAsync(f.Connection, p, p.ConfirmationText, Password, true);
                suite.False(result.Success); suite.Equal(0, result.AffectedRows); suite.Equal(before, await f.Value("SELECT password FROM jos_users WHERE id=1"));
            }
        });
        suite.Add("Preview connection identity includes SQLite file and prefix", async () =>
        {
            var first = await Fixture.Create(suite); var second = await Fixture.Create(suite); var service = new RecoveryService(new SqliteAccountRepository(true));
            var p = await service.PreviewAsync(Installation(first.Connection), first.Connection, 1, true, fallbackReason: Reason);
            await suite.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(second.Connection, p, p.ConfirmationText, Password, true));
            suite.Equal(InitialHash.Value, await first.Value("SELECT password FROM jos_users WHERE id=1")); suite.Equal(InitialHash.Value, await second.Value("SELECT password FROM jos_users WHERE id=1"));
            var secondPreview = await service.PreviewAsync(Installation(first.Connection), first.Connection, 1, true, fallbackReason: Reason);
            var changed = first.Connection.Copy(); changed.Prefix = "other_";
            await suite.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(changed, secondPreview, secondPreview.ConfirmationText, Password, true));
        });
        suite.Add("Expired and unknown repository nonces are refused", async () =>
        {
            var f = await Fixture.Create(suite); var clock = new FixtureClock(); var repo = new SqliteAccountRepository(true, clock); var service = new RecoveryService(repo, clock: clock);
            var p = await service.PreviewAsync(Installation(f.Connection), f.Connection, 1, true, fallbackReason: Reason); clock.Now += TimeSpan.FromMinutes(6);
            await suite.ThrowsAsync<InvalidOperationException>(() => service.ExecuteAsync(f.Connection, p, p.ConfirmationText, Password, true));
            await suite.ThrowsAsync<InvalidOperationException>(() => repo.ResetPasswordAsync(f.Connection, p with { PreviewId = "unissued" }, InitialHash.Value, default));
        });
        suite.Add("Verification failure rolls back password and triggered control change", async () =>
        {
            var f = await Fixture.Create(suite); var service = new RecoveryService(new SqliteAccountRepository(true));
            // Deliberate synthetic failure injection; production MySQL refuses trigger-bearing targets.
            await f.Sql("CREATE TRIGGER fixture_failure AFTER UPDATE OF password ON jos_users BEGIN UPDATE jos_users SET block=0 WHERE id=NEW.id; END");
            var p = await service.PreviewAsync(Installation(f.Connection), f.Connection, 1, true, fallbackReason: Reason);
            var result = await service.ExecuteAsync(f.Connection, p, p.ConfirmationText, Password, true);
            suite.False(result.Success); suite.Equal("REFUSED_OR_ROLLED_BACK", result.Outcome);
            suite.Equal(InitialHash.Value, await f.Value("SELECT password FROM jos_users WHERE id=1")); suite.Equal("1", await f.Value("SELECT block FROM jos_users WHERE id=1"));
        });
        suite.Add("Pre-execution cancellation cannot mutate an account", async () =>
        {
            var f = await Fixture.Create(suite); var service = new RecoveryService(new SqliteAccountRepository(true));
            var p = await service.PreviewAsync(Installation(f.Connection), f.Connection, 1, true, fallbackReason: Reason);
            using var cts = new CancellationTokenSource(); cts.Cancel();
            await suite.ThrowsAsync<OperationCanceledException>(() => service.ExecuteAsync(f.Connection, p, p.ConfirmationText, Password, true, cts.Token));
            suite.Equal(InitialHash.Value, await f.Value("SELECT password FROM jos_users WHERE id=1"));
        });
    }
    private static ConnectionSettings MySql() => new() { Engine = "mysql", Host = "localhost", Database = "joomla", Prefix = "jos_", Username = "fixture" };
    private static JoomlaInstallation Installation(ConnectionSettings connection) => new() { Id = "synthetic-installation", Name = "Synthetic test fixture", Version = "5.2.0", Configuration = new() { Status = VerificationStatus.Configured, Connection = connection.Copy() } };
    private sealed class FixtureClock : TimeProvider { public DateTimeOffset Now = DateTimeOffset.UtcNow; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Fixture(ConnectionSettings connection)
    {
        public ConnectionSettings Connection { get; } = connection;
        private SqliteConnection Open() => new(new SqliteConnectionStringBuilder { DataSource = Connection.SqlitePath, Pooling = false }.ConnectionString);
        public async Task Sql(string sql)
        {
            await using var db = Open(); await db.OpenAsync(); await using var cmd = db.CreateCommand(); cmd.CommandText = sql; await cmd.ExecuteNonQueryAsync();
        }
        public async Task<string> Value(string sql)
        {
            await using var db = Open(); await db.OpenAsync(); await using var cmd = db.CreateCommand(); cmd.CommandText = sql; return Convert.ToString(await cmd.ExecuteScalarAsync()) ?? "";
        }
        public async Task SetRules(string rules)
        {
            await using var db = Open(); await db.OpenAsync(); await using var cmd = db.CreateCommand();
            cmd.CommandText = "UPDATE jos_assets SET rules=@rules WHERE name='root.1'"; cmd.Parameters.AddWithValue("@rules", rules); await cmd.ExecuteNonQueryAsync();
        }
        public static async Task<Fixture> Create(TestSuite suite)
        {
            var path = Path.Combine(suite.NewDirectory("database-fixture"), "synthetic.sqlite");
            var f = new Fixture(new() { Engine = "sqlite", SqlitePath = path, Database = "synthetic_fixture", Prefix = "jos_", Username = "fixture" });
            await using var db = f.Open(); await db.OpenAsync(); await using var cmd = db.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE jos_users(id INTEGER PRIMARY KEY,username TEXT NOT NULL,name TEXT,email TEXT,password TEXT,block INTEGER,requireReset INTEGER,lastvisitDate TEXT);
                CREATE TABLE jos_user_usergroup_map(user_id INTEGER,group_id INTEGER);
                CREATE TABLE jos_usergroups(id INTEGER PRIMARY KEY,parent_id INTEGER,title TEXT,lft INTEGER,rgt INTEGER);
                CREATE TABLE jos_assets(id INTEGER PRIMARY KEY,parent_id INTEGER,name TEXT,rules TEXT);
                CREATE TABLE fixture_mfa(marker TEXT);
                INSERT INTO jos_users VALUES(1,'fixture_admin','Fixture Admin','fixture@example.invalid',@hash,1,1,NULL),(2,'second','Second','second@example.invalid',@hash,0,0,NULL);
                INSERT INTO jos_usergroups VALUES(1,0,'Public',1,8),(8,1,'Renamed privilege group',2,7),(9,8,'Child administrators',3,4);
                INSERT INTO jos_user_usergroup_map VALUES(1,9),(2,1);
                INSERT INTO jos_assets VALUES(1,0,'root.1','{"core.admin":{"8":true},"core.login.admin":{"8":true}}');
                INSERT INTO fixture_mfa VALUES('fixture-mfa-unchanged');
                """;
            cmd.Parameters.AddWithValue("@hash", InitialHash.Value); await cmd.ExecuteNonQueryAsync(); return f;
        }
    }
}
