using OmniRecovery.Tests;

var root=Path.GetFullPath(args.FirstOrDefault(x=>x.StartsWith("--work="))?[7..]??Path.Combine(Environment.CurrentDirectory,".local","tests",DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")));
var report=Path.GetFullPath(args.FirstOrDefault(x=>x.StartsWith("--report="))?[9..]??Path.Combine(Environment.CurrentDirectory,"artifacts","automated-tests.json"));
var suite=new TestSuite(root);
DiscoveryTests.Register(suite);
DatabaseTests.Register(suite);
var phpPathArgument=args.FirstOrDefault(x=>x.StartsWith("--php-path=",StringComparison.Ordinal));
if(phpPathArgument is not null) MariaDbIntegrationTests.RegisterPhp(suite,phpPathArgument[11..]);
var mariaDbPortArgument=args.FirstOrDefault(x=>x.StartsWith("--mariadb-port=",StringComparison.Ordinal));
if(mariaDbPortArgument is not null)
{
    if(!int.TryParse(mariaDbPortArgument[15..],out var mariaDbPort)) throw new ArgumentException("Invalid explicit disposable MariaDB port.");
    MariaDbIntegrationTests.Register(suite,mariaDbPort);
}
SecurityAiEvidenceTests.Register(suite);
return await suite.RunAsync(report);
