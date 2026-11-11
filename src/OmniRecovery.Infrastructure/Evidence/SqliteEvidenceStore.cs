using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Security;

namespace OmniRecovery.Infrastructure.Evidence;

public sealed class SqliteEvidenceStore : IEvidenceStore
{
    private readonly string _connection;
    private static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase) { "database", "table_prefix", "account_id", "role", "joomla_version", "installation_path", "connection_id", "action", "affected_rows", "record_verified", "duration_ms", "files", "directories" };
    public SqliteEvidenceStore(string directory)
    {
        SecretSafety.ProtectDirectory(directory);
        _connection=new SqliteConnectionStringBuilder{DataSource=Path.Combine(directory,"evidence.sqlite"),Mode=SqliteOpenMode.ReadWriteCreate,Pooling=false}.ToString();
        using var c=Open();using var cmd=c.CreateCommand();
        cmd.CommandText="PRAGMA secure_delete=ON; CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL,kind TEXT NOT NULL,installation_id TEXT NOT NULL,status TEXT NOT NULL,summary TEXT NOT NULL,metadata_json TEXT NOT NULL);";cmd.ExecuteNonQuery();
    }
    private SqliteConnection Open(){var c=new SqliteConnection(_connection);c.Open();return c;}
    public void Add(EvidenceEvent item)
    {
        var metadata=(item.Metadata??new Dictionary<string,string>()).Where(x=>Allowed.Contains(x.Key)).ToDictionary(x=>x.Key,x=>SecretSafety.Redact(x.Value));
        using var c=Open();using var q=c.CreateCommand();q.CommandText="INSERT INTO evidence(observed_at,kind,installation_id,status,summary,metadata_json) VALUES(@time,@kind,@installation,@status,@summary,@metadata)";
        q.Parameters.AddWithValue("@time",item.ObservedAt.ToString("O"));q.Parameters.AddWithValue("@kind",SecretSafety.Redact(item.Kind));q.Parameters.AddWithValue("@installation",item.InstallationId);q.Parameters.AddWithValue("@status",SecretSafety.Redact(item.Status));q.Parameters.AddWithValue("@summary",SecretSafety.Redact(item.Summary));q.Parameters.AddWithValue("@metadata",JsonSerializer.Serialize(metadata));q.ExecuteNonQuery();
    }
    public IReadOnlyList<EvidenceEvent> List(int limit=200)
    {
        using var c=Open();using var q=c.CreateCommand();q.CommandText="SELECT observed_at,kind,installation_id,status,summary,metadata_json FROM evidence ORDER BY id DESC LIMIT @limit";q.Parameters.AddWithValue("@limit",Math.Clamp(limit,1,10000));
        using var r=q.ExecuteReader();var rows=new List<EvidenceEvent>();
        while(r.Read())rows.Add(new(DateTimeOffset.Parse(r.GetString(0)),r.GetString(1),r.GetString(2),r.GetString(3),r.GetString(4),JsonSerializer.Deserialize<Dictionary<string,string>>(r.GetString(5))));return rows;
    }
    public void DeleteAll(){using var c=Open();using var q=c.CreateCommand();q.CommandText="PRAGMA secure_delete=ON; DELETE FROM evidence; VACUUM;";q.ExecuteNonQuery();}
    public void ExportJson(string path)=>File.WriteAllText(path,JsonSerializer.Serialize(new{schema_version="1.0",exported_at=DateTimeOffset.UtcNow,records=List(10000)},new JsonSerializerOptions{WriteIndented=true}));
    public void ExportCsv(string path)
    {
        static string Cell(string? value){var s=value??"";if(s.Length>0&&"=+-@\t\r".Contains(s[0]))s="'"+s;return "\""+s.Replace("\"","\"\"")+"\"";}
        var text=new StringBuilder("observed_at,kind,installation_id,status,summary\r\n");
        foreach(var x in List(10000))text.AppendLine(string.Join(",",new[]{x.ObservedAt.ToString("O"),x.Kind,x.InstallationId,x.Status,x.Summary}.Select(Cell)));File.WriteAllText(path,text.ToString(),Encoding.UTF8);
    }
}
