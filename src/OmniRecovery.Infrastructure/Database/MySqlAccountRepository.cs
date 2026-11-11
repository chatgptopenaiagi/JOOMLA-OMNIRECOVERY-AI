using System.Data.Common;
using System.Text.RegularExpressions;
using MySqlConnector;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Database;

public sealed class MySqlAccountRepository(TimeProvider? clock = null) : AccountRepositoryBase(clock)
{
    protected override bool IsSqlite => false;
    protected override DbConnection CreateConnection(ConnectionSettings settings, bool write)
    {
        SqlIntelligence.ValidateConnectionTarget(settings);
        if (settings.Engine.ToLowerInvariant() is not ("mysql" or "mysqli" or "mariadb")) throw new NotSupportedException("Expected a selected MySQL/MariaDB configuration.");
        var builder = new MySqlConnectionStringBuilder
        {
            Server = settings.Host, Port = settings.Port, Database = settings.Database, UserID = settings.Username, Password = settings.Password,
            ConnectionTimeout = 5, DefaultCommandTimeout = 10, Pooling = false, AllowLoadLocalInfile = false, AllowUserVariables = false,
            UseAffectedRows = true, PersistSecurityInfo = false, TreatTinyAsBoolean = false,
            SslMode = SqlIntelligence.IsLocalHost(settings.Host) ? MySqlSslMode.Preferred : MySqlSslMode.VerifyFull
        };
        return new MySqlConnection(builder.ConnectionString);
    }
    protected override async Task<SchemaInfo> ReadSchemaAsync(DbConnection db, ConnectionSettings settings, CancellationToken ct)
    {
        string version;
        await using (var command = Command(db, "SELECT VERSION()")) version = Convert.ToString(await command.ExecuteScalarAsync(ct)) ?? "UNKNOWN";
        var entries = new Dictionary<string, (string Engine, bool Base, HashSet<string> Columns, List<string> Primary)>(StringComparer.Ordinal);
        var parameters = new Dictionary<string,object?> { ["@database"] = settings.Database };
        await using (var command = Command(db, "SELECT TABLE_NAME,ENGINE,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=@database ORDER BY TABLE_NAME LIMIT 2001", parameters: parameters))
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                if (entries.Count >= 2000) throw new InvalidOperationException("Selected database table budget exceeded.");
                var name = reader.GetString(0);
                entries[name] = (reader.IsDBNull(1) ? "UNKNOWN" : reader.GetString(1), reader.GetString(2) == "BASE TABLE", new(StringComparer.OrdinalIgnoreCase), []);
            }
        }
        await using (var command = Command(db, "SELECT TABLE_NAME,COLUMN_NAME,COLUMN_KEY FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@database ORDER BY TABLE_NAME,ORDINAL_POSITION LIMIT 20001", parameters: parameters))
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            int count = 0;
            while (await reader.ReadAsync(ct))
            {
                if (++count > 20000) throw new InvalidOperationException("Selected database column budget exceeded.");
                if (entries.TryGetValue(reader.GetString(0), out var table)) { var column = reader.GetString(1); table.Columns.Add(column); if (reader.GetString(2) == "PRI") table.Primary.Add(column); }
            }
        }
        return new(version, entries.ToDictionary(x => x.Key, x => new TableSchema(x.Key, x.Value.Engine, x.Value.Columns, x.Value.Primary.Count == 1 && x.Value.Primary[0].Equals("id", StringComparison.OrdinalIgnoreCase), x.Value.Base), StringComparer.Ordinal));
    }
    protected override async Task EnsureWritableAsync(DbConnection db, ConnectionSettings settings, SchemaInfo schema, CancellationToken ct, DbTransaction? transaction = null)
    {
        if (!schema.Tables.TryGetValue(settings.Prefix + "users", out var users) || !users.Engine.Equals("InnoDB", StringComparison.OrdinalIgnoreCase) || !users.UniqueId)
            throw new InvalidOperationException("Direct fallback requires an InnoDB users table with a unique primary-key account identity.");
        await using (var engine = Command(db, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=@database AND TABLE_NAME=@table AND TABLE_TYPE='BASE TABLE'", transaction,
            new Dictionary<string,object?> { ["@database"] = settings.Database, ["@table"] = settings.Prefix + "users" }))
            if (!string.Equals(Convert.ToString(await engine.ExecuteScalarAsync(ct)), "InnoDB", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Current users storage engine is not InnoDB.");
        // information_schema.TRIGGERS hides rows without TRIGGER privilege. Empty metadata alone is not proof of no triggers.
        bool canInspectTriggers = false;
        await using (var grants = Command(db, "SHOW GRANTS FOR CURRENT_USER", transaction))
        await using (var reader = await grants.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                var grant = reader.GetString(0);
                var match = Regex.Match(grant, @"^GRANT (?<permissions>.+?) ON (?<scope>.+?) TO ", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (!match.Success) continue;
                var scope = match.Groups["scope"].Value;
                var selectedScope = scope == "*.*" || scope == SqlIntelligence.Quote(settings.Database) + ".*"
                    || scope == SqlIntelligence.Quote(settings.Database) + "." + Table(settings, "users");
                var permissions = match.Groups["permissions"].Value.Split(',').Select(p => p.Trim());
                if (selectedScope && permissions.Any(p => p.Equals("ALL PRIVILEGES", StringComparison.OrdinalIgnoreCase) || p.Equals("TRIGGER", StringComparison.OrdinalIgnoreCase))) canInspectTriggers = true;
            }
        }
        if (!canInspectTriggers) throw new InvalidOperationException("Trigger metadata visibility could not be established from direct grants. Role-only/partial privileges require supported Joomla recovery instead.");
        // An UPDATE trigger could change additional rows/fields outside the reviewed operation.
        await using var command = Command(db, "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=@database AND EVENT_OBJECT_TABLE=@table", transaction,
            new Dictionary<string,object?> { ["@database"] = settings.Database, ["@table"] = settings.Prefix + "users" });
        if (Convert.ToInt64(await command.ExecuteScalarAsync(ct)) != 0) throw new InvalidOperationException("Direct fallback is unavailable on a users table with triggers.");
    }
}
