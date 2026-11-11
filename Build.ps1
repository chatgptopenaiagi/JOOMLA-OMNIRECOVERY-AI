[CmdletBinding()]
param([switch]$SkipTests)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$projectRoot=$PSScriptRoot
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
$dotnet=Get-Command dotnet -ErrorAction SilentlyContinue
$dotnetPath=if($dotnet){$dotnet.Source}elseif(Test-Path 'C:\Program Files\dotnet\dotnet.exe'){'C:\Program Files\dotnet\dotnet.exe'}else{throw 'Install or select a .NET 10 SDK before building. This script does not install tools.'}
Push-Location $projectRoot
try {
    & $dotnetPath restore JoomlaOmniRecovery.slnx --packages .packages -p:NuGetAudit=false
    if($LASTEXITCODE -ne 0){throw 'Restore failed'}
    & $dotnetPath build JoomlaOmniRecovery.slnx -c Release --no-restore
    if($LASTEXITCODE -ne 0){throw 'Build failed'}
    if(-not $SkipTests){
        & $dotnetPath run --project tests/OmniRecovery.Tests -c Release --no-build -- --report=artifacts/automated-tests.json
        if($LASTEXITCODE -ne 0){throw 'Synthetic validation failed; release was not published'}
    }
    & $dotnetPath publish src/OmniRecovery.Desktop -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:DebugType=None -p:DebugSymbols=false -p:NuGetAudit=false -o release
    if($LASTEXITCODE -ne 0){throw 'Publish failed'}
    Copy-Item -LiteralPath (Join-Path $projectRoot 'Launch.cmd'),(Join-Path $projectRoot 'Launch-Demo.cmd') -Destination release
    Get-ChildItem -LiteralPath $projectRoot -Filter '*.md' -File | Where-Object Name -NotLike '*CHECKPOINT*' | Copy-Item -Destination release
    Copy-Item -LiteralPath (Join-Path $projectRoot 'config-templates') -Destination release -Recurse -Force
    if(Test-Path docs){Copy-Item -LiteralPath (Join-Path $projectRoot 'docs') -Destination release -Recurse -Force}
    if(Test-Path artifacts){
        New-Item -ItemType Directory -Path release/artifacts -Force | Out-Null
        foreach($publicReport in @('automated-tests.json','isolated-integration-tests.json','gui-verification.json','VERIFICATION-RESULTS.json','publication-review.json')){
            $publicPath=Join-Path artifacts $publicReport
            if(Test-Path -LiteralPath $publicPath){Copy-Item -LiteralPath $publicPath -Destination release/artifacts}
        }
    }
    if(Test-Path artifacts/VERIFICATION-RESULTS.json){Copy-Item artifacts/VERIFICATION-RESULTS.json release/VERIFICATION-RESULTS.json}
    Write-Output 'Published release/JOOMLA-OMNIRECOVERY-AI.exe'
} finally {Pop-Location}
