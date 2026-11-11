using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Database;

/// <summary>A deliberately small SELECT language, not an SQL sandbox.</summary>
public static class SqlIntelligence
{
    private static readonly Regex Identifier = new(@"^[A-Za-z_][A-Za-z0-9_]{0,63}$", RegexOptions.CultureInvariant);
    private static readonly Dictionary<string, string[]> Columns = new(StringComparer.OrdinalIgnoreCase)
    {
        ["users"] = ["id", "username", "name", "email", "block", "requireReset", "lastvisitDate", "registerDate", "sendEmail"],
        ["user_usergroup_map"] = ["user_id", "group_id"],
        ["usergroups"] = ["id", "parent_id", "title", "lft", "rgt"],
        ["assets"] = ["id", "parent_id", "name", "title", "rules", "lft", "rgt", "level"]
    };

    public static string ValidateIdentifier(string value)
    {
        if (string.IsNullOrEmpty(value) || !Identifier.IsMatch(value)) throw new ArgumentException("Unsafe or unsupported database identifier.");
        return value;
    }
    public static string ValidatePrefix(string prefix)
    {
        ValidateIdentifier(prefix);
        if (prefix.Length > 45 || !prefix.EndsWith('_')) throw new ArgumentException("A selected Joomla prefix ending in underscore is required.");
        return prefix;
    }
    public static bool IsLocalHost(string host) => string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
        || (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address));
    public static void ValidateConnectionTarget(ConnectionSettings connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (string.Equals(connection.Engine, "sqlite", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(connection.SqlitePath) || connection.SqlitePath == ":memory:" || !Path.IsPathFullyQualified(connection.SqlitePath))
                throw new ArgumentException("SQLite inspection requires an explicit absolute file path.");
            var path = Path.GetFullPath(connection.SqlitePath);
            if (path.StartsWith(@"\\") || path.StartsWith("//")) throw new ArgumentException("Network SQLite files are not supported.");
            return;
        }
        if (connection.Engine.ToLowerInvariant() is not ("mysql" or "mysqli" or "mariadb")) throw new NotSupportedException("Only MySQL/MariaDB and explicit SQLite inspection are supported.");
        ValidateIdentifier(connection.Database);
        if (connection.Port is 0 or > 65535) throw new ArgumentException("Invalid database port.");
        if (string.IsNullOrWhiteSpace(connection.Host) || connection.Host.Length > 253 || connection.Host.Any(char.IsWhiteSpace)
            || connection.Host.IndexOfAny([';', ',', '/', '\\', '=', '\0']) >= 0
            || (!IPAddress.TryParse(connection.Host, out _) && !Regex.IsMatch(connection.Host, @"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")))
            throw new ArgumentException("Invalid database host.");
        if (!IsLocalHost(connection.Host) && !connection.AllowRemote) throw new InvalidOperationException("Remote database access requires explicit opt-in.");
    }
    internal static string Fingerprint(ConnectionSettings c)
    {
        // Includes prefix, file and exact credential identity; no secret is returned or logged.
        var path = c.SqlitePath is null ? "" : Path.GetFullPath(c.SqlitePath);
        var text = System.Text.Json.JsonSerializer.Serialize(new[] { c.Engine.ToLowerInvariant(), c.Host.ToLowerInvariant(), c.Port.ToString(), c.Database, c.Username, c.Password, c.Prefix, path, c.AllowRemote.ToString() });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    }
    internal static string Quote(string identifier) => "`" + ValidateIdentifier(identifier) + "`";

    public static QueryPlan AccountListPlan(ConnectionSettings connection) => CreatePlan($"SELECT id, username, name, email, block, requireReset, lastvisitDate FROM {ValidatePrefix(connection.Prefix)}users ORDER BY id LIMIT 200", connection);

    public static QueryPlan CreatePlan(string sql, ConnectionSettings connection)
    {
        ValidateConnectionTarget(connection);
        ValidatePrefix(connection.Prefix);
        if (string.IsNullOrWhiteSpace(sql) || sql.Length > 8192) throw new ArgumentException("Enter a bounded SELECT statement.");
        var tokens = Tokenize(sql);
        var cursor = 0;
        string Take() => cursor < tokens.Count ? tokens[cursor++] : throw new ArgumentException("Incomplete SELECT statement.");
        bool Is(string value) => cursor < tokens.Count && tokens[cursor].Equals(value, StringComparison.OrdinalIgnoreCase);
        void Expect(string value) { if (!Take().Equals(value, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Unsupported SELECT grammar."); }
        Expect("SELECT");
        var selected = new List<string> { ValidateIdentifier(Take()) };
        while (Is(",")) { Take(); selected.Add(ValidateIdentifier(Take())); }
        Expect("FROM");
        var table = ValidateIdentifier(Take());
        if (!table.StartsWith(connection.Prefix, StringComparison.Ordinal)) throw new ArgumentException("Only the exact selected Joomla prefix can be queried.");
        var suffix = table[connection.Prefix.Length..];
        if (!Columns.TryGetValue(suffix, out var allowed)) throw new ArgumentException("This table is not in the read-only editor allowlist.");
        string Column(string value)
        {
            ValidateIdentifier(value);
            var known = allowed.FirstOrDefault(x => x.Equals(value, StringComparison.OrdinalIgnoreCase));
            return known is null ? throw new ArgumentException("Column is not in the safe editor allowlist; password and authentication material are excluded.") : Quote(known);
        }
        if (selected.Count > 20 || selected.Distinct(StringComparer.OrdinalIgnoreCase).Count() != selected.Count) throw new ArgumentException("Duplicate or excessive columns.");
        var result = new StringBuilder("SELECT " + string.Join(", ", selected.Select(Column)) + " FROM " + Quote(table));
        var parameters = new Dictionary<string, object?>();
        if (Is("WHERE"))
        {
            Take(); result.Append(" WHERE ");
            for (int count = 0; ; count++)
            {
                if (count >= 8) throw new ArgumentException("Too many predicates.");
                if (count > 0) result.Append(" AND ");
                result.Append(Column(Take()));
                var op = Take();
                if (op is not ("=" or "<>" or "<" or ">" or "<=" or ">=")) throw new ArgumentException("Only simple comparisons are supported.");
                var literal = Take(); object value;
                if (literal.StartsWith('\'')) value = literal[1..^1].Replace("''", "'");
                else if (long.TryParse(literal, out var number)) value = number;
                else throw new ArgumentException("Comparison values must be quoted text or integers.");
                var name = "@p" + parameters.Count;
                parameters[name] = value;
                result.Append(' ').Append(op).Append(' ').Append(name);
                if (!Is("AND")) break;
                Take();
            }
        }
        if (Is("ORDER"))
        {
            Take(); Expect("BY"); result.Append(" ORDER BY ").Append(Column(Take()));
            if (Is("ASC") || Is("DESC")) result.Append(' ').Append(Take().ToUpperInvariant());
        }
        var limit = 200;
        if (Is("LIMIT")) { Take(); if (!int.TryParse(Take(), out limit) || limit is < 1 or > 200) throw new ArgumentException("LIMIT must be between 1 and 200."); }
        if (cursor != tokens.Count) throw new ArgumentException("Only one allowlisted SELECT is supported; joins, subqueries, functions and comments are forbidden.");
        result.Append(" LIMIT ").Append(limit);
        return new("Bounded account/schema inspection", connection.Database, [table], result.ToString(), true, parameters);
    }

    internal static QueryPlan Revalidate(QueryPlan plan, ConnectionSettings connection)
    {
        // Never trust a caller-created QueryPlan or the ReadOnly flag. Rebuild the parsed language.
        if (!plan.ReadOnly || !string.Equals(plan.Database, connection.Database, StringComparison.Ordinal)) throw new ArgumentException("Query database differs from the selected configuration.");
        var literalSql = Regex.Replace(plan.Sql, @"@p\d+\b", m =>
        {
            if (!plan.Parameters.TryGetValue(m.Value, out var v)) throw new ArgumentException("Missing query parameter.");
            return v switch { string text => "'" + text.Replace("'", "''") + "'", long n => n.ToString(System.Globalization.CultureInfo.InvariantCulture), int n => n.ToString(System.Globalization.CultureInfo.InvariantCulture), _ => throw new ArgumentException("Unsupported query parameter type.") };
        });
        var validated = CreatePlan(literalSql, connection);
        if (!validated.Tables.SequenceEqual(plan.Tables, StringComparer.Ordinal)) throw new ArgumentException("Query table metadata mismatch.");
        return validated;
    }

    private static List<string> Tokenize(string sql)
    {
        var tokens = new List<string>();
        for (int i = 0; i < sql.Length;)
        {
            if (char.IsWhiteSpace(sql[i])) { i++; continue; }
            var start = i;
            if (sql[i] == '\'')
            {
                i++; bool closed = false;
                while (i < sql.Length)
                {
                    if (sql[i] == '\\' || char.IsControl(sql[i])) throw new ArgumentException("Backslash escapes and control characters are unsupported.");
                    if (sql[i++] != '\'') continue;
                    if (i < sql.Length && sql[i] == '\'') { i++; continue; }
                    closed = true; break;
                }
                if (!closed) throw new ArgumentException("Unclosed text literal.");
            }
            else if (sql[i] == '`')
            {
                var end = sql.IndexOf('`', i + 1);
                if (end < 0) throw new ArgumentException("Unclosed identifier.");
                tokens.Add(ValidateIdentifier(sql[(i + 1)..end])); i = end + 1;
                if (tokens.Count > 128) throw new ArgumentException("Statement is too complex.");
                continue;
            }
            else if (char.IsAsciiLetter(sql[i]) || sql[i] == '_') { i++; while (i < sql.Length && (char.IsAsciiLetterOrDigit(sql[i]) || sql[i] == '_')) i++; }
            else if (char.IsAsciiDigit(sql[i])) { i++; while (i < sql.Length && char.IsAsciiDigit(sql[i])) i++; }
            else if (sql[i] == ',') i++;
            else if (sql[i] is '=' or '<' or '>') { i++; if (i < sql.Length && (sql[i] == '=' || (sql[start] == '<' && sql[i] == '>'))) i++; }
            else throw new ArgumentException("Unsupported SQL token; comments, functions, qualification, wildcard and multiple statements are forbidden.");
            tokens.Add(sql[start..i]);
            if (tokens.Count > 128) throw new ArgumentException("Statement is too complex.");
        }
        return tokens;
    }
}
