#Requires -Version 5.1
[CmdletBinding()]
param([string]$PowerShellPath='', [switch]$RequireWindows51)
$ErrorActionPreference='Stop'
$env:POWERSHELL_TELEMETRY_OPTOUT='1';$env:POWERSHELL_UPDATECHECK='Off'
$root=Split-Path $PSScriptRoot -Parent
if($RequireWindows51 -and ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1)){
    throw 'This gate requires native Windows PowerShell 5.1 (Desktop edition).'
}
if(-not $PowerShellPath){$PowerShellPath=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName}
if(-not $env:COMPUTERNAME){$env:COMPUTERNAME='CI_SYNTHETIC_SENSOR'}
$outputDir=Join-Path $root 'artifacts';[void][IO.Directory]::CreateDirectory($outputDir)
Write-Host ('Candidate='+([IO.File]::ReadAllText((Join-Path $root 'VERSION')).Trim())+'; PS='+$PSVersionTable.PSVersion+'; Edition='+$PSVersionTable.PSEdition+'; CLR='+[Environment]::Version+'; OS='+[Environment]::OSVersion.VersionString)
function Invoke-CandidateCheck {
    param([string]$Name,[string[]]$Arguments)
    $output=& $PowerShellPath -NoLogo -NoProfile -ExecutionPolicy Bypass @Arguments 2>&1
    $code=$LASTEXITCODE
    $output | Tee-Object -FilePath (Join-Path $outputDir ($Name+'.txt')) | ForEach-Object{Write-Host $_}
    if($code -ne 0){throw ($Name+' failed with exit code '+$code+'. See artifacts/'+$Name+'.txt and any failure log.')}
}
Invoke-CandidateCheck 'selftest' @('-File',(Join-Path $root 'Network_Diagnostic_V2_12_RC3.ps1'),'-SelfTest')
Invoke-CandidateCheck 'integration' @('-File',(Join-Path $root 'Integration_Test.ps1'),'-PowerShellPath',$PowerShellPath)
Invoke-CandidateCheck 'portable-contract' @('-File',(Join-Path $root 'verification/Test_Portable_Contract.ps1'))
Write-Host 'CANDIDATE CHECKS PASSED. Native sensor deployment and router acceptance are separate gates.'
