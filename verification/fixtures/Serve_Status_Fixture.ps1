#Requires -Version 5.1
param([string]$StatusFile,[int]$Port=19763,[int]$DurationSec=90)
$ErrorActionPreference='Stop'
$root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $root 'lib/WebStatus.ps1')
$cfg=@{EnableWebStatus=$true;WebStatusPort=$Port}
$server=Start-WebStatus $cfg (Join-Path $root 'web')
$clock=[Diagnostics.Stopwatch]::StartNew();$last=''
try{
    while($clock.Elapsed.TotalSeconds -lt $DurationSec){
        $json=[IO.File]::ReadAllText($StatusFile)
        if($json -ne $last){$server.Publish($json);$last=$json}
        Start-Sleep -Milliseconds 100
    }
}finally{$server.Dispose()}
