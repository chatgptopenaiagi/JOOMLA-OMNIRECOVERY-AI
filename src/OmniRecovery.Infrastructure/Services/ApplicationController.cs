using System.Text.Json;
using Microsoft.Data.Sqlite;
using OmniRecovery.Core;
using OmniRecovery.Infrastructure.Ai;
using OmniRecovery.Infrastructure.Database;
using OmniRecovery.Infrastructure.Discovery;
using OmniRecovery.Infrastructure.Evidence;
using OmniRecovery.Infrastructure.Recovery;
using OmniRecovery.Infrastructure.Security;

namespace OmniRecovery.Infrastructure.Services;

public sealed class ApplicationSettings
{
    public ScanOptions Scan {get;set;}=new();
    public bool DarkTheme {get;set;}=true;
    public AiProviderSettings Ai {get;set;}=new();
}

public sealed class ApplicationController
{
    public bool IsDemo {get;}
    public string StateDirectory {get;}
    public IJoomlaDiscovery Discovery {get;}=new JoomlaDiscovery();
    public IConfigurationResolver Config {get;}=new StaticConfigurationResolver();
    public ISystemDiscovery System {get;}=new WindowsSystemDiscovery();
    public IEvidenceStore Evidence {get;}
    public ICredentialStore Credentials {get;}=new WindowsCredentialStore();
    public IPasswordHasher Passwords {get;}=new BCryptPasswordHasher();
    public AiAssistant Ai {get;}=new();
    public ApplicationSettings Settings {get;private set;}
    public SystemSnapshot? LastSystemSnapshot {get;private set;}
    private readonly MySqlAccountRepository _mysql=new();
    private readonly SqliteAccountRepository _sqlite;
    private readonly HashSet<string> _demoDatabases=new(StringComparer.OrdinalIgnoreCase);
    public ApplicationController(bool demo=false,string? stateDirectory=null)
    {
        IsDemo=demo;
        StateDirectory=stateDirectory??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"JoomlaOmniRecoveryAI",demo?"demo":"user");
        SecretSafety.ProtectDirectory(StateDirectory);
        _sqlite=new SqliteAccountRepository(allowSyntheticRecovery:demo);
        Evidence=new SqliteEvidenceStore(StateDirectory);
        var file=Path.Combine(StateDirectory,"settings.json");
        try{Settings=File.Exists(file)?JsonSerializer.Deserialize<ApplicationSettings>(File.ReadAllText(file))??new():new();}catch{Settings=new();}
        // Loading preferences never authorizes disclosure or connects to a provider.
    }
    public void SaveSettings()=>File.WriteAllText(Path.Combine(StateDirectory,"settings.json"),JsonSerializer.Serialize(Settings,new JsonSerializerOptions{WriteIndented=true}));
    public IAccountRepository Repository(ConnectionSettings connection)
    {
        if(connection.Engine.Equals("sqlite",StringComparison.OrdinalIgnoreCase))
        {
            if(IsDemo&&(!_demoDatabases.Contains(Path.GetFullPath(connection.SqlitePath??""))))throw new InvalidOperationException("Demo recovery is confined to the databases created for this application session.");
            return _sqlite;
        }
        if(IsDemo)throw new InvalidOperationException("Demo mode cannot connect to MySQL or MariaDB. Open normal mode for read-only owner-selected inspection.");
        return _mysql;
    }
    public async Task<ScanResult> ScanAsync(ScanOptions options,IProgress<ScanProgress>? progress,CancellationToken cancellationToken)
    {
        if(IsDemo)throw new InvalidOperationException("Demo mode uses synthetic installations only.");
        var result=await Discovery.ScanAsync(options,progress,cancellationToken);
        if(result.Cancelled||cancellationToken.IsCancellationRequested)
        {
            Evidence.Add(new(DateTimeOffset.UtcNow,"scan","","Cancelled","Partial installation markers preserved; configuration and database inspection were not continued."));
            return result with {Cancelled=true,Complete=false};
        }
        foreach(var installation in result.Installations)
        {
            if(cancellationToken.IsCancellationRequested)return result with {Cancelled=true,Complete=false};
            try { installation.Configuration=await Task.Run(()=>Config.Resolve(installation.ConfigurationPath,options.Roots),cancellationToken); }
            catch(OperationCanceledException){return result with {Cancelled=true,Complete=false};}
            Evidence.Add(new(DateTimeOffset.UtcNow,"installation",installation.Id,installation.Configuration.Status.ToString(),"Installation markers inspected; configuration resolved statically.",new Dictionary<string,string>{{"installation_path",installation.RootPath},{"joomla_version",installation.Version}}));
        }
        try
        {
            LastSystemSnapshot=await System.InspectAsync(options.Roots,cancellationToken);
            foreach(var installation in result.Installations)AssociateServer(installation,LastSystemSnapshot);
        }
        catch(OperationCanceledException){return result with {Cancelled=true,Complete=false};}
        catch(Exception ex){Evidence.Add(new(DateTimeOffset.UtcNow,"diagnostics","", "Error",SecretSafety.Error(ex)));}
        Evidence.Add(new(DateTimeOffset.UtcNow,"scan","",result.Cancelled?"Cancelled":result.Complete?"Complete":"Partial","Scoped discovery completed. A partial result does not prove absence.",new Dictionary<string,string>{{"files",result.FilesVisited.ToString()},{"directories",result.DirectoriesVisited.ToString()}}));
        return result;
    }
    public static void AssociateServer(JoomlaInstallation installation,SystemSnapshot snapshot)
    {
        static bool Within(string path,string root)=>Path.GetFullPath(path).Equals(Path.GetFullPath(root),StringComparison.OrdinalIgnoreCase)||Path.GetFullPath(path).StartsWith(Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase);
        var site=snapshot.ApacheSites.Where(s=>!string.IsNullOrWhiteSpace(s.DocumentRoot)&&Within(installation.RootPath,s.AliasTarget??s.DocumentRoot)).OrderByDescending(s=>(s.AliasTarget??s.DocumentRoot).Length).ThenBy(s=>s.Https).FirstOrDefault();
        if(site is not null)
        {
            var root=site.AliasTarget??site.DocumentRoot;
            var rel=Path.GetRelativePath(root,installation.RootPath).Replace('\\','/');
            if(rel==".")rel="";
            var prefix=(site.Alias??"").Trim('/');
            var path=string.Join('/',new[]{prefix,rel}.Where(x=>x.Length>0).SelectMany(x=>x.Split('/')).Select(Uri.EscapeDataString));
            var host=site.Host is "" or "_default_" or "*"?"localhost":site.Host;
            if(host.Contains(':')&&!host.StartsWith('['))host="localhost";
            var url=$"{(site.Https?"https":"http")}://{host}:{site.Port}/{path}".TrimEnd('/')+"/";
            if(Uri.TryCreate(url,UriKind.Absolute,out var uri)&&string.IsNullOrEmpty(uri.UserInfo)){installation.PublicUrl=url;installation.AdministratorUrl=url+"administrator/";}
            installation.ApacheConfiguration=site.ConfigurationPath;
        }
        installation.PhpExecutable=snapshot.Tools.FirstOrDefault(t=>t.Name.Contains("PHP",StringComparison.OrdinalIgnoreCase))?.Path;
    }
    public string? PhpMyAdminUrl()
    {
        var site=LastSystemSnapshot?.ApacheSites.FirstOrDefault(s=>(s.Alias??"").Contains("phpmyadmin",StringComparison.OrdinalIgnoreCase));
        if(site is null)return null;
        var host=site.Host is "" or "_default_" or "*"?"localhost":site.Host;
        return $"{(site.Https?"https":"http")}://{host}:{site.Port}/{site.Alias!.Trim('/')}/";
    }
    public async Task<IReadOnlyList<JoomlaInstallation>> CreateDemoAsync()
    {
        if(!IsDemo)throw new InvalidOperationException("Synthetic fixtures require demo mode.");
        var result=new List<JoomlaInstallation>();
        var session=Path.Combine(StateDirectory,"fixtures",Guid.NewGuid().ToString("N"));Directory.CreateDirectory(session);
        foreach(var label in new[]{"Alpha","Beta"})
        {
            var prefix=label.ToLowerInvariant()+"_";var root=Path.Combine(session,label,"public");var priv=Path.Combine(session,label,"private-config");
            Directory.CreateDirectory(root);Directory.CreateDirectory(priv);
            foreach(var part in new[]{"administrator","libraries/src","components","plugins","templates","media"})Directory.CreateDirectory(Path.Combine(root,part));
            File.WriteAllText(Path.Combine(root,"administrator/index.php"),"<?php // Synthetic marker only; not an executable Joomla distribution.");
            File.WriteAllText(Path.Combine(root,"configuration.php"),"<?php\n// Synthetic static loader.\nrequire_once __DIR__ . '/../private-config/configuration.php';\n");
            File.WriteAllText(Path.Combine(priv,"configuration.php"),"<?php\nclass JConfig { public $dbtype = 'mysqli'; public $host = 'localhost'; public $user = 'synthetic_fixture'; public $password = ''; public $db = 'synthetic_"+label.ToLowerInvariant()+"'; public $dbprefix = '"+prefix+"'; }\n");
            var db=Path.Combine(session,label,"fixture.sqlite");_demoDatabases.Add(Path.GetFullPath(db));
            await using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=db,Pooling=false}.ToString());await c.OpenAsync();
            await using var q=c.CreateCommand();q.CommandText=$"""
                CREATE TABLE {prefix}users(id INTEGER PRIMARY KEY,username TEXT NOT NULL,name TEXT NOT NULL,email TEXT NOT NULL,password TEXT NOT NULL,block INTEGER NOT NULL,requireReset INTEGER NOT NULL,lastvisitDate TEXT);
                CREATE TABLE {prefix}user_usergroup_map(user_id INTEGER NOT NULL,group_id INTEGER NOT NULL);
                CREATE TABLE {prefix}usergroups(id INTEGER PRIMARY KEY,parent_id INTEGER,title TEXT,lft INTEGER,rgt INTEGER);
                CREATE TABLE {prefix}assets(id INTEGER PRIMARY KEY,parent_id INTEGER,name TEXT,rules TEXT);
                INSERT INTO {prefix}usergroups VALUES(1,0,'Public',1,8),(2,1,'Registered',2,3),(7,1,'Administrators',4,5),(8,1,'Super Users',6,7);
                INSERT INTO {prefix}assets VALUES(1,0,'root.1',@rules);
                INSERT INTO {prefix}users VALUES(711,'owner_{label.ToLowerInvariant()}','Synthetic Owner','owner@example.invalid',@hash,0,0,NULL),(712,'editor_{label.ToLowerInvariant()}','Synthetic Editor','editor@example.invalid',@hash,0,0,NULL),(713,'blocked_{label.ToLowerInvariant()}','Synthetic Blocked Owner','blocked@example.invalid',@hash,1,1,NULL);
                INSERT INTO {prefix}user_usergroup_map VALUES(711,8),(712,2),(713,8);
                """;
            q.Parameters.AddWithValue("@hash",Passwords.Hash("Synthetic-Fixture-Only-2026!"));
            q.Parameters.AddWithValue("@rules","{\"core.admin\":{\"8\":true},\"core.login.admin\":{\"7\":true}}");await q.ExecuteNonQueryAsync();
            var settings=new ConnectionSettings{Engine="sqlite",Database="synthetic_"+label.ToLowerInvariant(),SqlitePath=db,Prefix=prefix,Username="synthetic_fixture",AuthenticationMethod="Isolated synthetic fixture"};
            result.Add(new JoomlaInstallation{Id=StableIdentity.For(root),Name="Training laboratory "+label,RootPath=root,ConfigurationPath=Path.Combine(root,"configuration.php"),Version="5.4.8",PublicUrl="http://localhost:18080/synthetic-"+label.ToLowerInvariant()+"/",AdministratorUrl=null,Status=VerificationStatus.Configured,Configuration=new ConfigurationResolution{Status=VerificationStatus.Configured,Connection=settings,EffectivePath=Path.Combine(priv,"configuration.php"),ReferenceChain=[Path.Combine(root,"configuration.php"),Path.Combine(priv,"configuration.php")]},Findings=[new("SYNTHETIC","Training database only. No actual Joomla login server is running.",VerificationStatus.NotTested)]});
        }
        LastSystemSnapshot=new("Synthetic fixture","Training owner",false,[new("PHP","synthetic-only","8.2.12",VerificationStatus.NotTested)],[new("Synthetic Apache","Training server","NotTested","not-running")],[],[new("synthetic-httpd.conf",session,"localhost",18080,false)], [new("DEMO","Port 18080 is a configuration fixture, not a running listener.",VerificationStatus.NotTested)]);
        Evidence.Add(new(DateTimeOffset.UtcNow,"demo","","Configured","Two independent synthetic installations created; no production connection."));return result;
    }
}
