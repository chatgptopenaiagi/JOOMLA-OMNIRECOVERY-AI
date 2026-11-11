using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Security;

namespace OmniRecovery.Infrastructure.Ai;

public sealed class AiProviderSettings
{
    public bool Enabled {get;set;}
    public string Provider {get;set;}="OpenAI-compatible";
    public string Endpoint {get;set;}="https://api.openai.com/v1/chat/completions";
    public string Model {get;set;}="";
}
public sealed class AiTechnicalContext
{
    public string JoomlaVersion {get;set;}="UNKNOWN";
    public string DatabaseStatus {get;set;}="NotTested";
    public string DatabaseEngine {get;set;}="UNKNOWN";
    public string ApacheStatus {get;set;}="NotTested";
    public string PhpVersion {get;set;}="UNKNOWN";
}
public sealed record AiDisclosure(string Id,string Endpoint,string JsonPreview);

public sealed class AiAssistant
{
    private readonly HttpClient _http;
    private readonly Dictionary<string,(string Digest,DateTimeOffset Expires)> _pending=[];
    public AiAssistant(HttpMessageHandler? handler=null)
    {
        _http=new HttpClient(handler??new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false}){Timeout=TimeSpan.FromSeconds(30)};
    }
    public static Uri ValidateEndpoint(string input)
    {
        if(!Uri.TryCreate(input,UriKind.Absolute,out var u)||u.Scheme!=Uri.UriSchemeHttps||!string.IsNullOrEmpty(u.UserInfo)||!string.IsNullOrEmpty(u.Query)||!string.IsNullOrEmpty(u.Fragment))
            throw new ArgumentException("Use an HTTPS API endpoint without credentials, query parameters or fragments.");
        return u;
    }
    public static string SanitizeQuestion(string question)
    {
        if(string.IsNullOrWhiteSpace(question)||question.Length>2000)throw new ArgumentException("Enter a technical question between 1 and 2,000 characters.");
        if(question.Contains("<?",StringComparison.Ordinal)||Regex.IsMatch(question,@"(?i)(password\s*[:=]|passwd\s*[:=]|pwd\s*[:=]|api[_ -]?key\s*[:=]|authorization\s*:|bearer\s+|secret\s*[:=]|token\s*[:=]|-----BEGIN|\$2[aby]\$|\$argon2|sk-(?:proj-)?[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{8,})"))
            throw new ArgumentException("The question appears to contain a credential, hash or configuration source. Remove it before using cloud assistance.");
        var s=Regex.Replace(question,@"(?i)[A-Z]:[\\/][^\r\n,;]*","[local path omitted]");
        s=Regex.Replace(s,@"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b","[email omitted]");
        s=Regex.Replace(s,@"https?://[^\s]+","[URL omitted]");
        return SecretSafety.Redact(s);
    }
    public AiDisclosure Prepare(AiProviderSettings settings,string question,AiTechnicalContext context)
    {
        if(!settings.Enabled)throw new InvalidOperationException("Cloud AI is disabled. Local guidance remains available.");
        var uri=ValidateEndpoint(settings.Endpoint);
        if(!Regex.IsMatch(settings.Model,@"\A[A-Za-z0-9._:/-]{1,128}\z"))throw new ArgumentException("Enter a model identifier provided by your AI provider.");
        static string Version(string s)=>Regex.IsMatch(s??"",@"\A\d{1,2}\.\d{1,2}(?:\.\d{1,3})?\z")?s??"UNKNOWN":"UNKNOWN";
        static string Status(string s)=>Enum.TryParse<VerificationStatus>(s,true,out var parsed)?parsed.ToString():s is "Running" or "Stopped"?s:"UNKNOWN";
        var safeContext=new {joomla_version=Version(context.JoomlaVersion),database_status=Status(context.DatabaseStatus),database_engine=context.DatabaseEngine.ToLowerInvariant() is "mysql" or "mariadb" or "sqlite" ? context.DatabaseEngine.ToLowerInvariant():"UNKNOWN",apache_status=Status(context.ApacheStatus),php_version=Version(context.PhpVersion)};
        var content="Technical question: "+SanitizeQuestion(question)+"\nSanitized context: "+JsonSerializer.Serialize(safeContext);
        var payload=JsonSerializer.Serialize(new { model=settings.Model,messages=new[]{new{role="system",content="You explain Joomla diagnostics. You have no tools, files, accounts or database access. Never request secrets or claim a password hash is reversible. Suggest supported recovery first. Any SQL is explanation only; local validation remains authoritative. State uncertainty."},new{role="user",content}},max_tokens=700},new JsonSerializerOptions{WriteIndented=true});
        var id=Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        lock(_pending){foreach(var old in _pending.Where(x=>x.Value.Expires<DateTimeOffset.UtcNow).Select(x=>x.Key).ToArray())_pending.Remove(old);_pending[id]=(Digest(uri.AbsoluteUri,payload),DateTimeOffset.UtcNow.AddMinutes(5));}
        return new(id,uri.AbsoluteUri,payload);
    }
    private static string Digest(string endpoint,string payload)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(endpoint+"\n"+payload)));
    public async Task<string> SendAsync(AiProviderSettings settings,AiDisclosure disclosure,string apiKey,bool approved,CancellationToken cancellationToken=default)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        cancellationToken=deadline.Token;
        if(!settings.Enabled||!approved)throw new InvalidOperationException("External disclosure was not approved.");
        var endpoint=ValidateEndpoint(settings.Endpoint).AbsoluteUri;
        lock(_pending)
        {
            if(!_pending.Remove(disclosure.Id,out var ticket)||ticket.Expires<DateTimeOffset.UtcNow||disclosure.Endpoint!=endpoint||ticket.Digest!=Digest(disclosure.Endpoint,disclosure.JsonPreview))throw new InvalidOperationException("The approved preview expired or changed. Preview the exact request again.");
        }
        if(string.IsNullOrWhiteSpace(apiKey)||apiKey.Any(char.IsControl))throw new ArgumentException("Configure an API key in the protected provider settings.");
        using var request=new HttpRequestMessage(HttpMethod.Post,endpoint);
        request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",apiKey);
        request.Content=new StringContent(disclosure.JsonPreview,Encoding.UTF8,"application/json");
        using var response=await _http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cancellationToken);
        if(!response.IsSuccessStatusCode)throw new InvalidOperationException($"AI provider returned HTTP {(int)response.StatusCode}. Check the endpoint, model, authorization and quota. Response bodies are not logged.");
        await using var stream=await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer=new MemoryStream();var bytes=new byte[4096];
        while(true){var n=await stream.ReadAsync(bytes,cancellationToken);if(n==0)break;if(buffer.Length+n>65536)throw new InvalidOperationException("The AI response exceeded the 64 KiB limit.");buffer.Write(bytes,0,n);}
        using var doc=JsonDocument.Parse(buffer.ToArray(),new JsonDocumentOptions{MaxDepth=24});
        if(!doc.RootElement.TryGetProperty("choices",out var choices)||choices.GetArrayLength()==0||!choices[0].TryGetProperty("message",out var msg)||!msg.TryGetProperty("content",out var answer)||answer.ValueKind!=JsonValueKind.String)throw new InvalidOperationException("The provider response did not match the documented chat-completions adapter.");
        return SecretSafety.Redact(answer.GetString()??string.Empty);
    }
}

public static class LocalAssistant
{
    public static string Answer(string question,JoomlaInstallation? installation=null,DatabaseInspection? database=null)
    {
        var intro=installation is null?"Select an installation after running a scoped scan.":$"Selected: {installation.Name}. Joomla version: {installation.Version}.";
        var q=question.ToLowerInvariant();
        if(q.Contains("password")||q.Contains("recover")||q.Contains("login"))return intro+"\n\n1. Resolve the selected Joomla configuration and review the database target.\n2. Connect with an authorized account and list user metadata.\n3. Prefer another authorized Super User or Joomla's supported console recovery. Joomla stores one-way hashes; an old plaintext password cannot be recovered.\n4. If supported recovery is unavailable, select exactly one account and review the version-gated database fallback.\n5. Enter a new password, review the target, and confirm the exact selected username. MFA, blocked status and active sessions remain separate issues.\n\nNo account has been changed by this guidance.";
        if(q.Contains("port")||q.Contains("apache")||q.Contains("10013"))return "Inspect Server diagnostics and compare configured ports with active listeners. A binding failure may involve another listener, HTTP.sys reservations, permission policy or excluded port ranges; an error code alone does not prove the cause. Keep working port choices. This application never stops services or rewrites Apache configuration. Review a specific repair plan separately.";
        if(q.Contains("database")||q.Contains("sql")||q.Contains("prefix"))return intro+"\n\nThe configured database and prefix are checked against users, user_usergroup_map, usergroups and assets. Group membership and root ACL grants inform administrator status; uncertain permissions stay explicit. The SQL workbench accepts a restricted SELECT grammar over approved nonsecret account columns. Recovery writes are unavailable from that editor.";
        if(q.Contains("cloud")||q.Contains("ai")||q.Contains("privacy"))return "Local discovery, account inspection and recovery work without cloud AI. Cloud assistance requires a configured provider, a protected API key and approval of the exact sanitized request preview. Configuration files, passwords, hashes, cookies, account lists and database exports are never attached. AI responses cannot execute SQL or recovery actions.";
        return intro+"\n\nI can guide you through installation discovery, database configuration, account identification, password recovery, Apache diagnostics and privacy settings. Local rules remain authoritative. Choose a question such as 'I forgot my Joomla password' or 'Why is the database unavailable?'";
    }
}
