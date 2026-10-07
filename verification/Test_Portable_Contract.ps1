#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
foreach($lib in @('AddressPolicy','Core')){. (Join-Path $root ('lib/'+$lib+'.ps1'))}
$fixture=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'fixtures/core-rc31.json') | ConvertFrom-Json
$cfg=$fixture.config;$count=0
foreach($case in $fixture.cases){
    $latest=@{};$state=New-IncidentState
    foreach($step in $case.steps){
        foreach($row in $step.rows){$latest[$row.Protocol+':'+$row.Name+':'+$row.Scope+':'+$row.Data.QueryName]=$row}
        $assessment=Get-CoreAssessment @($latest.Values) $step.nowMs $cfg
        $actions=@(Update-IncidentState $state $assessment @($latest.Values) $step.nowMs $cfg)
        if($assessment.Code -ne $step.expectedCode -or $state.Active -ne $step.expectedActive -or ($actions -join ',') -ne ($step.expectedActions -join ',')){throw ('Portable contract failed: '+$case.name+' at '+$step.nowMs)}
        $count++;Write-Host ('PASS '+$case.name+' @ '+$step.nowMs)
    }
}
Write-Host ('PORTABLE CONTRACT PASSED: '+$count+' state transitions; no native APIs or network.')
