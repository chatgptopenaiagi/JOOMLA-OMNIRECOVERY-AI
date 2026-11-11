using System.Net;
using System.Text;
using System.Text.Json;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Ai;
using OmniRecovery.Infrastructure.Security;
using OmniRecovery.Infrastructure.Evidence;
using OmniRecovery.Infrastructure.Discovery;

namespace OmniRecovery.Tests;
public static class SecurityAiEvidenceTests
{
    public static void Register(TestSuite t)
    {
        t.Add("HTTP reachability rejects remote targets and credential-bearing URLs",async()=>
        {
            foreach(var uri in new[]{"http://example.invalid/administrator/","http://localhost.evil.invalid/","http://user:secret@localhost/","http://localhost/?token=fixture","file:///C:/Windows/"})
                t.Equal(VerificationStatus.Unsupported,(await SiteReachability.CheckAsync(uri)).Status);
        });
        t.Add("HTTP reachability uses unauthenticated HEAD and does not follow redirect",async()=>
        {
            var listener=new System.Net.Sockets.TcpListener(IPAddress.Loopback,0);listener.Start();
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
            try
            {
                var port=((IPEndPoint)listener.LocalEndpoint).Port;
                var server=Task.Run(async()=>
                {
                    using var client=await listener.AcceptTcpClientAsync(timeout.Token);await using var stream=client.GetStream();
                    using var reader=new StreamReader(stream,Encoding.ASCII,false,4096,true);
                    var request=await reader.ReadLineAsync(timeout.Token);t.Equal("HEAD /administrator/ HTTP/1.1",request);
                    var lines=0;while(await reader.ReadLineAsync(timeout.Token) is {Length:>0} line){if(++lines>40)throw new Exception("Header budget exceeded");t.False(line.StartsWith("Authorization:",StringComparison.OrdinalIgnoreCase));t.False(line.StartsWith("Cookie:",StringComparison.OrdinalIgnoreCase));}
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 302 Found\r\nLocation: https://example.invalid/never-follow\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),timeout.Token);
                });
                var result=await SiteReachability.CheckAsync($"http://127.0.0.1:{port}/administrator/",timeout.Token);
                await server;t.Equal(VerificationStatus.Accessible,result.Status);t.True(result.Message.Contains("302"));
            }
            finally{timeout.Cancel();listener.Stop();}
        });
        t.Add("Secret properties never serialize",()=>
        {
            var c=new ConnectionSettings{Password="synthetic-private-value"};
            var json=JsonSerializer.Serialize(c);t.False(json.Contains(c.Password));t.False(c.ToString().Contains(c.Password));
            t.False(JsonSerializer.Serialize(new ConfigurationResolution{Connection=c}).Contains(c.Password));
        });
        t.Add("Secret redaction removes credential assignments and hashes",()=>
        {
            var input="password='fixture-value' api_key=fixture-api-value "+"$2y$12$"+new string('a',53);
            var safe=SecretSafety.Redact(input);t.False(safe.Contains("fixture-value"));t.False(safe.Contains("fixture-api-value"));t.False(safe.Contains("$2y$"));
        });
        t.Add("Credential Manager round trip confined to app target",()=>
        {
            var store=new WindowsCredentialStore();var target="synthetic-test-"+Guid.NewGuid().ToString("N");
            try{store.Save(target,"fixture","synthetic-test-only");var value=store.Read(target);t.True(value.HasValue);t.Equal("synthetic-test-only",value!.Value.Secret);}
            finally{store.Delete(target);}
            t.True(store.Read(target) is null);t.Throws<ArgumentException>(()=>store.Read("../unrelated-target"));
        });
        t.Add("Evidence persistence excludes unknown secret metadata",()=>
        {
            var store=new SqliteEvidenceStore(t.NewDirectory("evidence"));
            store.Add(new(DateTimeOffset.UtcNow,"fixture","id","Verified","password='synthetic-hidden'",new Dictionary<string,string>{{"account_id","711"},{"password","synthetic-hidden"}}));
            var rows=store.List();t.Equal(1,rows.Count);t.True(rows[0].Metadata!.ContainsKey("account_id"));t.False(rows[0].Metadata!.ContainsKey("password"));t.False(rows[0].Summary.Contains("synthetic-hidden"));
            var file=Path.Combine(t.NewDirectory("export"),"safe.json");store.ExportJson(file);t.False(File.ReadAllText(file).Contains("synthetic-hidden"));store.DeleteAll();t.Equal(0,store.List().Count);
        });
        t.Add("CSV export neutralizes spreadsheet formulas",()=>
        {
            var dir=t.NewDirectory("csv");var store=new SqliteEvidenceStore(dir);store.Add(new(DateTimeOffset.UtcNow,"=1+1","fixture","Verified","safe"));var file=Path.Combine(dir,"export.csv");store.ExportCsv(file);t.True(File.ReadAllText(file).Contains("'=1+1"));
        });
        t.Add("Cloud disabled makes no network request",()=>
        {
            var handler=new FakeHandler();var ai=new AiAssistant(handler);t.Throws<InvalidOperationException>(()=>ai.Prepare(new(),"Explain database connection failures",new()));t.Equal(0,handler.Requests);
            t.True(LocalAssistant.Answer("forgot password").Contains("one-way"));
        });
        t.Add("Cloud context excludes paths account data and raw config",()=>
        {
            var ai=new AiAssistant(new FakeHandler());var d=ai.Prepare(Settings(),"PHP failure for person@example.invalid at C:\\private\\config.php",new(){JoomlaVersion="5.4.8",DatabaseEngine="mysql",DatabaseStatus="Configured",ApacheStatus="Running",PhpVersion="8.2.12"});
            t.False(d.JsonPreview.Contains("person@example.invalid"));t.False(d.JsonPreview.Contains("private"));t.True(d.JsonPreview.Contains("5.4.8"));
            t.Throws<ArgumentException>(()=>ai.Prepare(Settings(),"password=synthetic-secret",new()));t.Throws<ArgumentException>(()=>ai.Prepare(Settings(),"<?php public $password",new()));
        });
        t.Add("Cloud requires exact one-use disclosure approval",async()=>
        {
            var handler=new FakeHandler();var ai=new AiAssistant(handler);var settings=Settings();var d=ai.Prepare(settings,"Explain Joomla recovery",new());
            await t.ThrowsAsync<InvalidOperationException>(()=>ai.SendAsync(settings,d,"synthetic-key",false));t.Equal(0,handler.Requests);
            var text=await ai.SendAsync(settings,d,"synthetic-key",true);t.Equal("Synthetic provider explanation",text);t.Equal(1,handler.Requests);
            await t.ThrowsAsync<InvalidOperationException>(()=>ai.SendAsync(settings,d,"synthetic-key",true));
            var changed=ai.Prepare(settings,"Explain Joomla recovery",new());await t.ThrowsAsync<InvalidOperationException>(()=>ai.SendAsync(settings,changed with{JsonPreview="{}"},"synthetic-key",true));
        });
        t.Add("Cloud endpoint blocks insecure credentialed URLs",()=>
        {
            t.Throws<ArgumentException>(()=>AiAssistant.ValidateEndpoint("http://example.invalid/v1"));t.Throws<ArgumentException>(()=>AiAssistant.ValidateEndpoint("https://user:secret@example.invalid/v1"));t.Throws<ArgumentException>(()=>AiAssistant.ValidateEndpoint("https://example.invalid/v1?token=synthetic"));
        });
        t.Add("Cloud provider errors never echo response body",async()=>
        {
            var ai=new AiAssistant(new FakeHandler{Failure=true});var s=Settings();var d=ai.Prepare(s,"Explain connection failure",new());
            try{await ai.SendAsync(s,d,"synthetic-key",true);throw new Exception("Expected provider failure");}
            catch(InvalidOperationException ex){t.False(ex.Message.Contains("synthetic-secret"));t.True(ex.Message.Contains("401"));}
        });
        t.Add("Cloud cancellation is propagated",async()=>
        {
            var ai=new AiAssistant(new FakeHandler{Wait=true});var s=Settings();var d=ai.Prepare(s,"Explain connection failure",new());using var cancel=new CancellationTokenSource(20);
            await t.ThrowsAsync<OperationCanceledException>(()=>ai.SendAsync(s,d,"synthetic-key",true,cancel.Token));
        });
    }
    private static AiProviderSettings Settings()=>new(){Enabled=true,Endpoint="https://api.example.invalid/v1/chat/completions",Model="synthetic-model"};
    private sealed class FakeHandler : HttpMessageHandler
    {
        public int Requests;public bool Failure,Wait;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            Requests++;if(Wait)await Task.Delay(Timeout.Infinite,ct);
            return new(Failure?HttpStatusCode.Unauthorized:HttpStatusCode.OK){Content=new StringContent(Failure?"synthetic-secret":"{\"choices\":[{\"message\":{\"content\":\"Synthetic provider explanation\"}}]}",Encoding.UTF8,"application/json")};
        }
    }
}
