using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace OmniRecovery.Core;

public enum VerificationStatus { Discovered, Configured, Accessible, Verified, Unavailable, AuthenticationFailed, NotTested, Error, NeedsApproval, Unsupported }
public sealed record Finding(string Code, string Message, VerificationStatus Status, string? Source = null);
public sealed class ScanOptions
{
    public List<string> Roots { get; set; } = [@"C:\xampp", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)];
    public int MaxDepth { get; set; } = 7;
    public int MaxFiles { get; set; } = 25000;
    public int MaxDirectories { get; set; } = 6000;
    public int MaxSeconds { get; set; } = 45;
    public List<string> ExcludedDirectories { get; set; } = [".git", "node_modules", ".venv", "venv", "vendor", "cache", "caches", "tmp", "temp", "bin", "obj", "build", "dist", "Windows", "Browser", "Google", "Mozilla", "MicrosoftEdge", "Cookies", ".ssh", ".aws", ".azure", "Credentials", "Packages", "$Recycle.Bin", "System Volume Information", ".packages", ".local"];
}
public sealed record ScanProgress(int Directories, int Files, int Installations, string CurrentPath, string Message);
public sealed record ScanResult(IReadOnlyList<JoomlaInstallation> Installations, IReadOnlyList<Finding> Findings, int DirectoriesVisited, int FilesVisited, bool Complete, bool Cancelled, DateTimeOffset StartedAt, DateTimeOffset FinishedAt);
public sealed class JoomlaInstallation
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string RootPath { get; set; } = "";
    public string ConfigurationPath { get; set; } = "";
    public string Version { get; set; } = "UNKNOWN";
    public string? PublicUrl { get; set; }
    public string? AdministratorUrl { get; set; }
    public string? PhpExecutable { get; set; }
    public string? ApacheConfiguration { get; set; }
    public VerificationStatus Status { get; set; } = VerificationStatus.Discovered;
    public List<Finding> Findings { get; set; } = [];
    [JsonIgnore] public ConfigurationResolution? Configuration { get; set; }
    public string Display => $"{Name} · Joomla {Version}";
    public override string ToString() => Display;
}
public sealed class ConnectionSettings
{
    public string Engine { get; set; } = "mysql";
    public string Host { get; set; } = "localhost";
    public uint Port { get; set; } = 3306;
    public string Database { get; set; } = "";
    public string Username { get; set; } = "";
    [JsonIgnore] public string Password { get; set; } = "";
    public string Prefix { get; set; } = "";
    public bool AllowRemote { get; set; }
    public string? SqlitePath { get; set; }
    public string AuthenticationMethod { get; set; } = "Selected Joomla configuration";
    public string Id => StableIdentity.For($"{Engine}|{Host}|{Port}|{Database}|{Username}");
    public override string ToString() => $"{Engine}://{Host}:{Port}/{Database} (credentials hidden)";
    public ConnectionSettings Copy() => new() { Engine=Engine, Host=Host, Port=Port, Database=Database, Username=Username, Password=Password, Prefix=Prefix, AllowRemote=AllowRemote, SqlitePath=SqlitePath, AuthenticationMethod=AuthenticationMethod };
}
public sealed class ConfigurationResolution
{
    public VerificationStatus Status { get; set; }
    [JsonIgnore] public ConnectionSettings? Connection { get; set; }
    public string? EffectivePath { get; set; }
    public List<string> ReferenceChain { get; set; } = [];
    public List<string> PendingApprovalPaths { get; set; } = [];
    public List<string> UnresolvedFields { get; set; } = [];
    public List<Finding> Findings { get; set; } = [];
    public string? LiveSite { get; set; }
    public override string ToString() => $"Configuration {Status}; {ReferenceChain.Count} files; secret values hidden";
}
public sealed record AccountInfo(long Id, string Username, string DisplayName, string Email, bool Blocked, string Groups, string AdministratorPrivileges, string? LastVisit, bool RequireReset, string? Notes = null);
public sealed record DatabaseInspection(VerificationStatus Status, string EngineVersion, string Database, string Prefix, IReadOnlyList<string> Tables, IReadOnlyList<AccountInfo> Accounts, IReadOnlyList<Finding> Findings);
public sealed record QueryPlan(string Purpose, string Database, IReadOnlyList<string> Tables, string Sql, bool ReadOnly, IReadOnlyDictionary<string, object?> Parameters);
public sealed record QueryResult(IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<object?>> Rows, bool Truncated = false);
public sealed record RecoveryPreview(string PreviewId, string InstallationId, string InstallationName, string JoomlaVersion, string Database, string Prefix, long AccountId, string Username, string Method, string SqlPreview, string ConfirmationText, DateTimeOffset ExpiresAt, IReadOnlyList<string> Warnings);
public sealed record RecoveryOutcome(bool Success, string Outcome, int AffectedRows, bool RecordVerified, string Message, DateTimeOffset CompletedAt);
public sealed record EvidenceEvent(DateTimeOffset ObservedAt, string Kind, string InstallationId, string Status, string Summary, IReadOnlyDictionary<string,string>? Metadata = null);
public sealed record ToolObservation(string Name, string Path, string Version, VerificationStatus Status);
public sealed record ServiceObservation(string Name, string DisplayName, string Status, string Executable);
public sealed record ApacheSite(string ConfigurationPath, string DocumentRoot, string Host, int Port, bool Https, string? Alias = null, string? AliasTarget = null);
public sealed record SystemSnapshot(string WindowsVersion, string UserIdentity, bool IsAdministrator, IReadOnlyList<ToolObservation> Tools, IReadOnlyList<ServiceObservation> Services, IReadOnlyList<int> ListeningPorts, IReadOnlyList<ApacheSite> ApacheSites, IReadOnlyList<Finding> Findings);
public static class StableIdentity { public static string For(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value.ToLowerInvariant().Replace('\\','/'))))[..24].ToLowerInvariant(); }

public interface IJoomlaDiscovery { Task<ScanResult> ScanAsync(ScanOptions options, IProgress<ScanProgress>? progress, CancellationToken cancellationToken); }
public interface IConfigurationResolver { ConfigurationResolution Resolve(string configurationPath, IReadOnlyCollection<string> approvedRoots, IReadOnlyCollection<string>? explicitlyApprovedFiles = null); }
public interface ISystemDiscovery { Task<SystemSnapshot> InspectAsync(IReadOnlyCollection<string> roots, CancellationToken cancellationToken); }
public interface IAccountRepository
{
    Task<DatabaseInspection> InspectAsync(ConnectionSettings connection, CancellationToken cancellationToken);
    Task<QueryResult> ExecuteReadOnlyAsync(ConnectionSettings connection, QueryPlan plan, CancellationToken cancellationToken);
    Task<RecoveryOutcome> ResetPasswordAsync(ConnectionSettings connection, RecoveryPreview preview, string newPasswordHash, CancellationToken cancellationToken);
}
public interface IPasswordHasher { string Hash(string password); bool Verify(string password, string hash); string GeneratePassword(); }
public interface ICredentialStore { void Save(string target, string username, string secret); (string Username,string Secret)? Read(string target); void Delete(string target); }
public interface IEvidenceStore { void Add(EvidenceEvent item); IReadOnlyList<EvidenceEvent> List(int limit = 200); void DeleteAll(); void ExportJson(string path); void ExportCsv(string path); }
