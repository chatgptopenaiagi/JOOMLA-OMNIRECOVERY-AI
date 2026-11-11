[CmdletBinding()]
param([string]$MariaDbBin='C:\xampp\mysql\bin',[string]$PhpPath='C:\xampp\php\php.exe')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
$dotnetCommand=Get-Command dotnet -ErrorAction SilentlyContinue
$dotnetPath=if($dotnetCommand){$dotnetCommand.Source}else{'C:\Program Files\dotnet\dotnet.exe'}
$initializer=Join-Path $MariaDbBin 'mysql_install_db.exe'
$serverExecutable=Join-Path $MariaDbBin 'mysqld.exe'
$adminExecutable=Join-Path $MariaDbBin 'mysqladmin.exe'
foreach($required in @($dotnetPath,$initializer,$serverExecutable,$adminExecutable,$PhpPath)){if(-not(Test-Path -LiteralPath $required -PathType Leaf)){throw "Required existing tool unavailable: $required"}}
$fixtureRoot=Join-Path $PSScriptRoot ('.local\mdb-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,4))
$expectedPrefix=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '.local')).TrimEnd('\')+'\'
if(-not [IO.Path]::GetFullPath($fixtureRoot).StartsWith($expectedPrefix,[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture scope validation failed'}
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
# Use an unprivileged port below the Windows dynamic range for older MariaDB test binaries.
$fixturePort=0
foreach($candidatePort in (@(13377)+@(1..20 | ForEach-Object {Get-Random -Minimum 10000 -Maximum 30000}))){
    $portProbe=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$candidatePort)
    try{$portProbe.Start();$fixturePort=$candidatePort;break}catch{}finally{$portProbe.Stop()}
}
if($fixturePort -eq 0){throw 'No available isolated test port found'}
$bootstrap=$null
$server=$null
Push-Location $PSScriptRoot
try {
    $bootstrap=Start-Process -FilePath $initializer -ArgumentList @('--datadir="'+$fixtureRoot+'\data"',"--port=$fixturePort") -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $fixtureRoot 'bootstrap-output.log') -RedirectStandardError (Join-Path $fixtureRoot 'bootstrap-error.log')
    if(-not $bootstrap.WaitForExit(45000)){ $bootstrap.Kill();throw 'Disposable initialization deadline exceeded' }
    if($bootstrap.ExitCode -ne 0){throw 'Disposable initialization failed; inspect private fixture logs'}
    $fixtureIni=Join-Path $fixtureRoot 'fixture.ini'
    @"
[mysqld]
basedir=$((Split-Path $MariaDbBin -Parent).Replace('\','/'))
datadir=$($fixtureRoot.Replace('\','/'))/data
port=$fixturePort
bind-address=127.0.0.1
skip-name-resolve
skip-log-bin
log-error=$($fixtureRoot.Replace('\','/'))/server-error.log
pid-file=$($fixtureRoot.Replace('\','/'))/server.pid
max_connections=8
innodb_buffer_pool_size=32M
"@ | Set-Content -LiteralPath $fixtureIni
    $server=Start-Process -FilePath $serverExecutable -ArgumentList ('--defaults-file="'+$fixtureIni+'"') -WindowStyle Hidden -PassThru
    $ready=$false
    $readinessClock=[Diagnostics.Stopwatch]::StartNew()
    while($readinessClock.Elapsed.TotalSeconds -lt 30){
        if($server.HasExited){throw ('Disposable server exited before protocol readiness; exit='+$server.ExitCode+'. See private fixture logs; no production connection attempted.')}
        $pingOutput=Join-Path $fixtureRoot 'ping-output.log'
        $ping=Start-Process -FilePath $adminExecutable -ArgumentList @('--no-defaults','--host=127.0.0.1',"--port=$fixturePort",'--user=root','--connect-timeout=1','ping') -WindowStyle Hidden -PassThru -RedirectStandardOutput $pingOutput -RedirectStandardError (Join-Path $fixtureRoot 'ping-error.log')
        if(-not $ping.WaitForExit(2000)){$ping.Kill();$ping.WaitForExit(1000)|Out-Null}
        elseif($ping.ExitCode -eq 0 -and (Get-Content -LiteralPath $pingOutput -Raw).Contains('mysqld is alive')){$ready=$true;break}
        Start-Sleep -Milliseconds 200
    }
    if(-not $ready){throw 'Disposable server readiness deadline exceeded'}
    & $dotnetPath run --project tests/OmniRecovery.Tests -c Release -p:NuGetAudit=false -- "--mariadb-port=$fixturePort" "--php-path=$PhpPath" --report=artifacts/isolated-integration-tests.json
    if($LASTEXITCODE -ne 0){throw 'Isolated integration checks failed'}
} finally {
    if($server -and -not $server.HasExited){
        $metadata=Get-CimInstance Win32_Process -Filter ('ProcessId='+$server.Id)
        if($metadata -and $metadata.CommandLine.Contains($fixtureIni) -and $metadata.ExecutablePath -eq [IO.Path]::GetFullPath($serverExecutable)){$server.Kill();$server.WaitForExit(5000)|Out-Null}
        else{Write-Warning 'Process identity changed; no unrelated process was stopped.'}
    }
    Pop-Location
}
# Preserve only disposable fixture data for diagnosis. No existing MariaDB service is touched.
