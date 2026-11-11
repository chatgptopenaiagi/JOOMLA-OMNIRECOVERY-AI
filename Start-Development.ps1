[CmdletBinding()]
param([switch]$Demo)
$ErrorActionPreference='Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
$sdk=Get-Command dotnet -ErrorAction SilentlyContinue
$dotnetPath=if($sdk){$sdk.Source}elseif(Test-Path 'C:\Program Files\dotnet\dotnet.exe'){'C:\Program Files\dotnet\dotnet.exe'}else{throw 'A .NET 10 SDK is required for development. Use the self-contained release instead.'}
Push-Location $PSScriptRoot
try {
    $appArguments=if($Demo){@('--demo')}else{@()}
    & $dotnetPath run --project src/OmniRecovery.Desktop -c Release -- @appArguments
    if($LASTEXITCODE -ne 0){throw 'Development application failed'}
} finally {Pop-Location}
