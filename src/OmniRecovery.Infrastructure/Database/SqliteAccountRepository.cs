using System.Data.Common;
using Microsoft.Data.Sqlite;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Database;

/// <summary>Generic read-only inspection, plus explicitly enabled synthetic fixture transactions. Not a production Joomla backend.</summary>
public sealed class SqliteAccountRepository(bool allowSyntheticRecovery = false, TimeProvider? clock = null) : AccountRepositoryBase(clock)
{
    protected override bool IsSqlite => true;
    protected override bool RecoveryAllowed => allowSyntheticRecovery;
    protected override string LockClause => ""; // SQLite serializable write transaction supplies the fixture lock.
    protected override DbConnection CreateConnection(ConnectionSettings settings, bool write)
    {
        SqlIntelligence.ValidateConnectionTarget(settings);
        if (!settings.Engine.Equals("sqlite", StringComparison.OrdinalIgnoreCase)) throw new NotSupportedException("Expected an explicit SQLite file configuration.");
        if (!File.Exists(settings.SqlitePath)) throw new FileNotFoundException("Selected SQLite file does not exist.");
        if (write && !allowSyntheticRecovery) throw new NotSupportedException("SQLite is read-only unless synthetic fixture mode was explicitly enabled.");
        return new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.GetFullPath(settings.SqlitePath!), Mode = write ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private, Pooling = false, DefaultTimeout = 5, ForeignKeys = true
        }.ConnectionString);
    }
    protected override async Task<SchemaInfo> ReadSchemaAsync(DbConnection db, ConnectionSettings settings, CancellationToken ct)
    {
        string version;
        await using (var command = Command(db, "SELECT sqlite_version()")) version = "SQLite " + Convert.ToString(await command.ExecuteScalarAsync(ct));
        var tables = new Dictionary<string, TableSchema>(StringComparer.Ordinal);
        var names = new List<string>();
        await using (var command = Command(db, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 2001"))
        await using (var reader = await command.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct)) { if (names.Count >= 2000) throw new InvalidOperationException("SQLite table budget exceeded."); names.Add(reader.GetString(0)); }
        foreach (var name in names)
        {
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var primary = new List<string>();
            // Only inspect identifier-safe Joomla-shaped tables. Generic table names remain visible, never interpolated.
            if (RequiredColumns.Keys.Any(suffix => name.EndsWith(suffix, StringComparison.Ordinal)))
            {
                try { SqlIntelligence.ValidateIdentifier(name); } catch (ArgumentException) { tables[name] = new(name, "SQLite", columns, false); continue; }
                await using var command = Command(db, "PRAGMA table_info(" + SqlIntelligence.Quote(name) + ")");
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct)) { var column = reader.GetString(1); columns.Add(column); if (reader.GetInt32(5) > 0) primary.Add(column); }
            }
            tables[name] = new(name, "SQLite", columns, primary.Count == 1 && primary[0].Equals("id", StringComparison.OrdinalIgnoreCase));
        }
        return new(version, tables);
    }
    protected override Task EnsureWritableAsync(DbConnection db, ConnectionSettings settings, SchemaInfo schema, CancellationToken ct, DbTransaction? transaction = null)
    {
        if (!allowSyntheticRecovery) throw new NotSupportedException("Production Joomla SQLite recovery is unsupported.");
        if (!schema.Tables[settings.Prefix + "users"].UniqueId) throw new InvalidOperationException("Synthetic recovery requires a unique account primary key.");
        ct.ThrowIfCancellationRequested(); return Task.CompletedTask;
    }
}
