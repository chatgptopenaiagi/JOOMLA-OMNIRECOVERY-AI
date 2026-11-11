using System.Collections.Concurrent;
using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Database;

public interface IRecoveryPreviewRepository
{
    Task<RecoveryPreview> CreateRecoveryPreviewAsync(JoomlaInstallation installation, ConnectionSettings connection, long accountId, CancellationToken cancellationToken);
}

public abstract class AccountRepositoryBase : IAccountRepository, IRecoveryPreviewRepository
{
    protected sealed record TableSchema(string Name, string Engine, HashSet<string> Columns, bool UniqueId, bool BaseTable = true);
    protected sealed record SchemaInfo(string Version, Dictionary<string, TableSchema> Tables);
    private sealed record AccountState(long Id, string Username, string Hash, bool Blocked, bool RequireReset);
    private sealed record IssuedPreview(RecoveryPreview Preview, string ConnectionFingerprint, AccountState Account);
    private readonly ConcurrentDictionary<string, IssuedPreview> previews = new(StringComparer.Ordinal);
    protected readonly TimeProvider Clock;
    protected AccountRepositoryBase(TimeProvider? clock = null) => Clock = clock ?? TimeProvider.System;
    protected abstract bool IsSqlite { get; }
    protected virtual bool RecoveryAllowed => !IsSqlite;
    protected abstract DbConnection CreateConnection(ConnectionSettings settings, bool write);
    protected abstract Task<SchemaInfo> ReadSchemaAsync(DbConnection db, ConnectionSettings settings, CancellationToken ct);
    protected abstract Task EnsureWritableAsync(DbConnection db, ConnectionSettings settings, SchemaInfo schema, CancellationToken ct, DbTransaction? transaction = null);
    protected virtual string LockClause => " FOR UPDATE";

    protected static DbCommand Command(DbConnection db, string sql, DbTransaction? transaction = null, IReadOnlyDictionary<string, object?>? parameters = null)
    {
        var command = db.CreateCommand(); command.CommandText = sql; command.CommandTimeout = 10; command.Transaction = transaction;
        if (parameters is not null) foreach (var pair in parameters) { var p = command.CreateParameter(); p.ParameterName = pair.Key; p.Value = pair.Value ?? DBNull.Value; command.Parameters.Add(p); }
        return command;
    }
    protected static string Table(ConnectionSettings c, string suffix) => SqlIntelligence.Quote(SqlIntelligence.ValidatePrefix(c.Prefix) + suffix);
    protected static readonly Dictionary<string, string[]> RequiredColumns = new()
    {
        ["users"] = ["id", "username", "name", "email", "password", "block", "requireReset", "lastvisitDate"],
        ["user_usergroup_map"] = ["user_id", "group_id"],
        ["usergroups"] = ["id", "parent_id", "title", "lft", "rgt"],
        ["assets"] = ["id", "parent_id", "name", "rules"]
    };
    protected static bool ValidSchema(SchemaInfo schema, string prefix)
    {
        foreach (var required in RequiredColumns)
            if (!schema.Tables.TryGetValue(prefix + required.Key, out var table) || !table.BaseTable || !required.Value.All(table.Columns.Contains)) return false;
        return schema.Tables[prefix + "users"].UniqueId;
    }
    private static void RequireSchema(SchemaInfo schema, string prefix)
    {
        SqlIntelligence.ValidatePrefix(prefix);
        if (!ValidSchema(schema, prefix)) throw new InvalidOperationException("The exact configured prefix does not have the required Joomla users, mapping, groups and assets schema with unique user identity.");
    }

    public async Task<DatabaseInspection> InspectAsync(ConnectionSettings connection, CancellationToken cancellationToken)
    {
        var c = connection.Copy(); SqlIntelligence.ValidateConnectionTarget(c);
        var findings = new List<Finding>();
        try
        {
            await using var db = CreateConnection(c, false); await db.OpenAsync(cancellationToken);
            var schema = await ReadSchemaAsync(db, c, cancellationToken);
            var tables = schema.Tables.Keys.Order(StringComparer.Ordinal).Take(2000).ToArray();
            var validPrefix = false;
            try { SqlIntelligence.ValidatePrefix(c.Prefix); validPrefix = ValidSchema(schema, c.Prefix); } catch (ArgumentException) { }
            if (!validPrefix)
            {
                var candidates = schema.Tables.Keys.Where(t => t.EndsWith("users", StringComparison.Ordinal)).Select(t => t[..^5])
                    .Where(p => p.Length > 0 && ValidSchema(schema, p)).Take(10).ToArray();
                findings.Add(new("PREFIX_SCHEMA_MISMATCH", "The exact selected prefix is not a validated Joomla schema. No account target was selected and no automatic prefix fallback is allowed.", VerificationStatus.Unsupported));
                if (candidates.Length > 0) findings.Add(new("PREFIX_CANDIDATES", "Schema-validated candidates for manual configuration review: " + string.Join(", ", candidates), VerificationStatus.NotTested));
                if (IsSqlite) findings.Add(new("SQLITE_GENERIC_ONLY", "Generic SQLite file inspection only. SQLite is not a supported production Joomla recovery backend.", VerificationStatus.Unsupported));
                return new(VerificationStatus.Accessible, schema.Version, c.Database, c.Prefix, tables, [], findings);
            }
            var accounts = await ReadAccountsAsync(db, c, findings, cancellationToken);
            findings.Add(new("ACL_SCOPE", "Group labels and root asset rules are evidence, not a full Joomla authorization decision. Group inheritance is inspected; component/action overrides and extensions remain site-specific. Group 8 alone never establishes administrator rights.", VerificationStatus.NotTested));
            if (IsSqlite) findings.Add(new("SQLITE_NOT_PRODUCTION", "SQLite is inspection/demo support only; no production Joomla compatibility or login is established.", VerificationStatus.Unsupported));
            return new(VerificationStatus.Verified, schema.Version, c.Database, c.Prefix, tables, accounts, findings);
        }
        catch (OperationCanceledException) { throw; }
        catch (DbException ex)
        {
            var authentication = ex is MySqlConnector.MySqlException m && m.Number is 1044 or 1045;
            return new(authentication ? VerificationStatus.AuthenticationFailed : VerificationStatus.Unavailable, "UNKNOWN", c.Database, c.Prefix, [], [],
                [new("DATABASE_UNAVAILABLE", authentication ? "Selected configuration authentication was refused. Credentials are hidden." : "Selected database could not be inspected. No alternate database was attempted.", authentication ? VerificationStatus.AuthenticationFailed : VerificationStatus.Unavailable)]);
        }
    }

    private async Task<IReadOnlyList<AccountInfo>> ReadAccountsAsync(DbConnection db, ConnectionSettings c, List<Finding> findings, CancellationToken ct)
    {
        var groups = new Dictionary<long, (long Parent, string Title)>();
        await using (var cmd = Command(db, $"SELECT id,parent_id,title FROM {Table(c, "usergroups")} LIMIT 1001"))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct)) { if (groups.Count >= 1000) throw new InvalidOperationException("Group inspection budget exceeded."); groups[Convert.ToInt64(reader.GetValue(0))] = (Convert.ToInt64(reader.GetValue(1)), Convert.ToString(reader.GetValue(2)) ?? ""); }
        var memberships = new Dictionary<long, List<long>>(); bool membershipIncomplete = false;
        await using (var cmd = Command(db, $"SELECT user_id,group_id FROM {Table(c, "user_usergroup_map")} ORDER BY user_id LIMIT 10001"))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            int count = 0;
            while (await reader.ReadAsync(ct))
            {
                if (++count > 10000) { membershipIncomplete = true; findings.Add(new("MEMBERSHIP_LIMIT", "Membership inspection truncated; privilege labels may be incomplete.", VerificationStatus.NotTested)); break; }
                var id = Convert.ToInt64(reader.GetValue(0)); if (!memberships.TryGetValue(id, out var values)) memberships[id] = values = [];
                values.Add(Convert.ToInt64(reader.GetValue(1)));
            }
        }
        // Inspect asset parent inheritance separately from group inheritance. Root grants alone are not component ACL evaluation.
        var assets = new Dictionary<long, (long Parent, string Name)>(); bool assetIncomplete = false;
        await using (var cmd = Command(db, $"SELECT id,parent_id,name FROM {Table(c, "assets")} ORDER BY id LIMIT 2001"))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct))
            {
                if (assets.Count >= 2000) { assetIncomplete = true; break; }
                assets[Convert.ToInt64(reader.GetValue(0))] = (Convert.ToInt64(reader.GetValue(1)), Convert.ToString(reader.GetValue(2)) ?? "");
            }
        var roots = assets.Where(x => x.Value.Name == "root.1" && x.Value.Parent == 0).Select(x => x.Key).ToArray();
        if (roots.Length != 1) assetIncomplete = true;
        else foreach (var asset in assets.Keys)
        {
            long current = asset; var seen = new HashSet<long>();
            while (current != roots[0])
            {
                if (current == 0 || !seen.Add(current) || seen.Count > 100 || !assets.TryGetValue(current, out var row)) { assetIncomplete = true; break; }
                current = row.Parent;
            }
        }
        findings.Add(new("ASSET_INHERITANCE", assetIncomplete ? "Asset inheritance contains gaps, cycles, multiple roots or exceeds the inspection budget; effective ACL remains unknown."
            : "Inspected asset parent chains reach root.1. Action-specific rule precedence and extension authorization are still not evaluated.", assetIncomplete ? VerificationStatus.NotTested : VerificationStatus.Verified));
        string? rules = null; int rootCount = 0;
        await using (var cmd = Command(db, $"SELECT parent_id,rules FROM {Table(c, "assets")} WHERE name=@name LIMIT 2", parameters: new Dictionary<string,object?> { ["@name"] = "root.1" }))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct)) { rootCount++; if (Convert.ToInt64(reader.GetValue(0)) == 0) rules = Convert.ToString(reader.GetValue(1)); }
        if (rootCount != 1 || rules is null || rules.Length > 32768) rules = null;
        var output = new List<AccountInfo>();
        await using (var cmd = Command(db, $"SELECT id,username,name,email,block,requireReset,lastvisitDate FROM {Table(c, "users")} ORDER BY id LIMIT 201"))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                if (output.Count == 200) { findings.Add(new("ACCOUNT_LIMIT", "Only the first 200 accounts are shown. Use a bounded account query for further inspection.", VerificationStatus.NotTested)); break; }
                var id = Convert.ToInt64(reader.GetValue(0)); var assigned = memberships.GetValueOrDefault(id) ?? [];
                var inherited = new HashSet<long>(); bool incomplete = assetIncomplete || membershipIncomplete;
                foreach (var group in assigned)
                {
                    var seen = new HashSet<long>(); long current = group;
                    while (current != 0)
                    {
                        if (!seen.Add(current) || seen.Count > 100 || !groups.TryGetValue(current, out var row)) { incomplete = true; break; }
                        inherited.Add(current); current = row.Parent;
                    }
                }
                var privilege = DescribePrivileges(rules, inherited, incomplete);
                output.Add(new(id, Convert.ToString(reader.GetValue(1)) ?? "", Convert.ToString(reader.GetValue(2)) ?? "", Convert.ToString(reader.GetValue(3)) ?? "",
                    Convert.ToInt64(reader.GetValue(4)) != 0, string.Join(", ", assigned.Select(g => groups.TryGetValue(g, out var gr) ? gr.Title : "Unknown group " + g)), privilege,
                    reader.IsDBNull(6) ? null : Convert.ToString(reader.GetValue(6), CultureInfo.InvariantCulture), Convert.ToInt64(reader.GetValue(5)) != 0,
                    "Effective authorization must be confirmed in Joomla; account block, MFA and session state are preserved."));
            }
        }
        return output;
    }
    private static string DescribePrivileges(string? json, HashSet<long> groups, bool incomplete)
    {
        if (incomplete || json is null) return "Unknown: incomplete group/root asset inheritance";
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 12 });
            (bool Grant, bool Deny, bool Unsupported) ReadAction(string action)
            {
                if (!doc.RootElement.TryGetProperty(action, out var rule)) return (false, false, false);
                if (rule.ValueKind != JsonValueKind.Object) return (false, false, true);
                bool grant = false, deny = false, unsupported = false;
                var properties = rule.EnumerateObject().ToArray();
                if (properties.Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != properties.Length) unsupported = true;
                foreach (var id in groups)
                {
                    if (!rule.TryGetProperty(id.ToString(CultureInfo.InvariantCulture), out var value)) continue;
                    if (value.ValueKind == JsonValueKind.True) grant = true;
                    else if (value.ValueKind == JsonValueKind.False) deny = true;
                    else if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) && number is 0 or 1)
                    { if (number == 1) grant = true; else deny = true; }
                    else unsupported = true;
                }
                return (grant, deny, unsupported);
            }
            var root = doc.RootElement.EnumerateObject().ToArray();
            if (root.Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != root.Length) return "Unknown: duplicate root ACL action definitions";
            var admin = ReadAction("core.admin"); var login = ReadAction("core.login.admin");
            if (admin.Unsupported || login.Unsupported) return "Unknown: unsupported root ACL permission values";
            if ((admin.Grant && admin.Deny) || (login.Grant && login.Deny)) return "Conflicting root ACL grant/deny evidence; effective site ACL unverified";
            if (admin.Grant) return "Root core.admin grant detected (including group ancestors); effective site ACL unverified";
            if (login.Grant) return "Root administrator-login grant detected; effective site ACL unverified";
            if (admin.Deny || login.Deny) return "Root ACL deny evidence detected; effective site ACL unverified";
            return "Administrator privileges not established by inspected root ACL";
        }
        catch (JsonException) { return "Unknown: root ACL JSON could not be interpreted"; }
        catch (InvalidOperationException) { return "Unknown: root ACL structure unsupported"; }
    }

    public async Task<QueryResult> ExecuteReadOnlyAsync(ConnectionSettings connection, QueryPlan plan, CancellationToken cancellationToken)
    {
        var c = connection.Copy(); var safe = SqlIntelligence.Revalidate(plan, c);
        await using var db = CreateConnection(c, false); await db.OpenAsync(cancellationToken);
        var schema = await ReadSchemaAsync(db, c, cancellationToken); RequireSchema(schema, c.Prefix);
        await using var command = Command(db, safe.Sql, parameters: safe.Parameters);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var columns = Enumerable.Range(0, reader.FieldCount).Select(reader.GetName).ToArray();
        if (columns.Any(x => x.Equals("password", StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("Authentication material is excluded.");
        var rows = new List<IReadOnlyList<object?>>();
        while (await reader.ReadAsync(cancellationToken))
        {
            if (rows.Count >= 200) return new(columns, rows, true);
            rows.Add(Enumerable.Range(0, reader.FieldCount).Select(i => reader.IsDBNull(i) ? null : reader.GetValue(i)).ToArray());
        }
        return new(columns, rows, rows.Count == 200);
    }

    public async Task<RecoveryPreview> CreateRecoveryPreviewAsync(JoomlaInstallation installation, ConnectionSettings connection, long accountId, CancellationToken cancellationToken)
    {
        if (!RecoveryAllowed) throw new NotSupportedException("Production Joomla recovery via SQLite is unsupported.");
        Recovery.RecoveryService.RequireSupportedVersion(installation.Version);
        Recovery.RecoveryService.RequireTargetBinding(installation, connection);
        var c = connection.Copy(); SqlIntelligence.ValidateConnectionTarget(c); SqlIntelligence.ValidatePrefix(c.Prefix);
        if (accountId <= 0 || string.IsNullOrWhiteSpace(installation.Id)) throw new ArgumentException("An exact installation and account identity is required.");
        await using var db = CreateConnection(c, false); await db.OpenAsync(cancellationToken);
        var schema = await ReadSchemaAsync(db, c, cancellationToken); RequireSchema(schema, c.Prefix);
        await EnsureWritableAsync(db, c, schema, cancellationToken);
        var account = await ReadAccountStateAsync(db, c, accountId, null, false, cancellationToken);
        foreach (var old in previews.Where(p => p.Value.Preview.ExpiresAt <= Clock.GetUtcNow()).Select(p => p.Key)) previews.TryRemove(old, out _);
        if (previews.Count >= 100) throw new InvalidOperationException("Too many outstanding previews; let existing previews expire.");
        var preview = new RecoveryPreview(Convert.ToHexString(RandomNumberGenerator.GetBytes(24)), installation.Id, installation.Name, installation.Version, c.Database, c.Prefix,
            account.Id, account.Username, IsSqlite ? "SYNTHETIC SQLITE FIXTURE ONLY" : "Explicit direct database fallback: bcrypt password field only",
            $"UPDATE {SqlIntelligence.Quote(c.Database.Length > 0 ? c.Database : "fixture")}.{Table(c, "users")} SET password=@newPasswordHash WHERE id=@accountId AND username=@username AND password=@expectedHash;",
            "RESET " + account.Username, Clock.GetUtcNow().AddMinutes(5),
            ["Use Joomla-supported recovery and an authorized administrator first. This is an explicitly opted-in fallback.", "Only the selected password field changes. Block, requireReset, MFA, groups and sessions are preserved.", "Database verification is not proof that Joomla login works. Review active sessions and change the temporary password through Joomla after recovery.", "Preview expires in five minutes and is consumed by one attempt. A changed row or connection requires a new preview."]);
        if (!previews.TryAdd(preview.PreviewId, new(preview, SqlIntelligence.Fingerprint(c), account))) throw new InvalidOperationException("Could not issue preview.");
        return preview;
    }

    private async Task<AccountState> ReadAccountStateAsync(DbConnection db, ConnectionSettings c, long id, DbTransaction? transaction, bool lockRow, CancellationToken ct)
    {
        await using var command = Command(db, $"SELECT id,username,password,block,requireReset FROM {Table(c, "users")} WHERE id=@id" + (lockRow ? LockClause : ""), transaction, new Dictionary<string,object?> { ["@id"] = id });
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) throw new InvalidOperationException("The selected account no longer exists.");
        var state = new AccountState(Convert.ToInt64(reader.GetValue(0)), Convert.ToString(reader.GetValue(1)) ?? "", Convert.ToString(reader.GetValue(2)) ?? "", Convert.ToInt64(reader.GetValue(3)) != 0, Convert.ToInt64(reader.GetValue(4)) != 0);
        if (await reader.ReadAsync(ct)) throw new InvalidOperationException("Account identity is not unique.");
        return state;
    }
    public async Task<RecoveryOutcome> ResetPasswordAsync(ConnectionSettings connection, RecoveryPreview preview, string newPasswordHash, CancellationToken cancellationToken)
    {
        if (!RecoveryAllowed) throw new NotSupportedException("Production Joomla recovery via SQLite is unsupported.");
        var c = connection.Copy(); SqlIntelligence.ValidateConnectionTarget(c); SqlIntelligence.ValidatePrefix(c.Prefix);
        Recovery.RecoveryService.RequireSupportedVersion(preview.JoomlaVersion);
        if (!Regex.IsMatch(newPasswordHash ?? "", @"^\$2y\$12\$[./A-Za-z0-9]{53}$", RegexOptions.CultureInvariant)) throw new ArgumentException("A supported bcrypt hash is required.");
        if (!previews.TryRemove(preview.PreviewId, out var issued) || issued.Preview != preview || preview.ExpiresAt <= Clock.GetUtcNow()
            || !string.Equals(issued.ConnectionFingerprint, SqlIntelligence.Fingerprint(c), StringComparison.Ordinal))
            throw new InvalidOperationException("Preview is invalid, changed, expired, consumed, or belongs to another connection.");
        DbTransaction? transaction = null; bool commitStarted = false;
        await using var db = CreateConnection(c, true);
        try
        {
            await db.OpenAsync(cancellationToken);
            var schema = await ReadSchemaAsync(db, c, cancellationToken); RequireSchema(schema, c.Prefix);
            await EnsureWritableAsync(db, c, schema, cancellationToken);
            transaction = await db.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
            var current = await ReadAccountStateAsync(db, c, preview.AccountId, transaction, true, cancellationToken);
            // Recheck engine/trigger visibility after the users SELECT holds its metadata lock; avoid a pre-transaction DDL race.
            await EnsureWritableAsync(db, c, schema, cancellationToken, transaction);
            if (current != issued.Account || current.Username != preview.Username || current.Id != preview.AccountId) throw new InvalidOperationException("The account changed after preview.");
            await using (var command = Command(db, $"UPDATE {Table(c, "users")} SET password=@newHash WHERE id=@id AND username=@username AND password=@oldHash", transaction,
                new Dictionary<string,object?> { ["@newHash"] = newPasswordHash, ["@id"] = current.Id, ["@username"] = current.Username, ["@oldHash"] = current.Hash }))
                if (await command.ExecuteNonQueryAsync(cancellationToken) != 1) throw new InvalidOperationException("Expected exactly one changed account.");
            var verified = await ReadAccountStateAsync(db, c, current.Id, transaction, false, cancellationToken);
            if (verified.Hash != newPasswordHash || verified.Id != current.Id || verified.Username != current.Username || verified.Blocked != current.Blocked || verified.RequireReset != current.RequireReset)
                throw new InvalidOperationException("Transactional verification failed.");
            commitStarted = true; await transaction.CommitAsync(cancellationToken);
            return new(true, IsSqlite ? "SYNTHETIC_RESET_VERIFIED" : "PASSWORD_FIELD_UPDATED", 1, true, "Exactly one password field was committed after transactional verification. Joomla login, MFA and active-session behavior are not verified.", Clock.GetUtcNow());
        }
        catch (Exception ex) when (ex is DbException or InvalidOperationException or OperationCanceledException)
        {
            if (commitStarted) return new(false, "COMMIT_OUTCOME_UNKNOWN", 0, false, "Commit acknowledgement was interrupted. Do not retry automatically; inspect the account through Joomla.", Clock.GetUtcNow());
            var rolledBack = transaction is null;
            if (transaction is not null) try { await transaction.RollbackAsync(CancellationToken.None); rolledBack = true; } catch (DbException) { }
            return new(false, rolledBack ? "REFUSED_OR_ROLLED_BACK" : "ROLLBACK_UNCONFIRMED", 0, false,
                rolledBack ? "Recovery was refused or rolled back because identity, schema, cancellation or verification checks failed. No successful reset is claimed." : "Rollback could not be confirmed. Inspect the account before any retry.", Clock.GetUtcNow());
        }
        finally { if (transaction is not null) await transaction.DisposeAsync(); }
    }
}
