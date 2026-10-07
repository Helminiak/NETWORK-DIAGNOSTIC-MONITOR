#Requires -Version 5.1
[CmdletBinding()]
param([string]$PowerShellPath='')
$ErrorActionPreference='Stop'
if(-not $PowerShellPath){$PowerShellPath=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('NetDiagIntegration_'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
$child=$null;$count=0
function Assert-Integration {param([bool]$Condition,[string]$Name);if(-not $Condition){throw ('INTEGRATION FAILED: '+$Name)};$script:count++;Write-Host ('PASS '+$Name)}
try{
    $source=Join-Path $fixture 'Source';Copy-Item -LiteralPath $PSScriptRoot -Destination $source -Recurse
    # Explicit test adapters only in this disposable copy. Production sources remain
    # unchanged. No external DNS, ICMP, HTTP, Windows tasks, power or capture calls.
    $runtime=@'
function Get-SensorContext {
    param($Config)
    [pscustomobject]@{RouteInfo=[pscustomobject]@{Gateway='127.0.0.1';InterfaceIndex=1;AdapterName='INTEGRATION_STUB';LinkSpeed='TEST';SystemDns='127.0.0.1'};Targets=@([pscustomobject]@{Name='Default-Gateway';IP='127.0.0.1';Provider='Local';Role='Gateway'});AllDnsResolvers=@([pscustomobject]@{Name='System-Default';IP='127.0.0.1';Class='System';Scope='RouterDNS';Provider='Router'});TransportResolvers=@();SystemDnsRole='ROUTER';CurlExe=$null}
}
'@
    [IO.File]::AppendAllText((Join-Path $source 'lib/Runtime.ps1'),"`n"+$runtime)
    # This container cannot expose Process.StartTime. This substitution is isolated
    # and declared; real Windows PID/start-time validation remains untested.
    [IO.File]::AppendAllText((Join-Path $source 'lib/Deployment.ps1'),"`nfunction Get-ProcessStartIdentity {param([int]`$ProcessId=`$PID);return 'INTEGRATION_START_ADAPTER'}`n")
    $probe=@'
function Invoke-ProbeFamily {
    $target=[pscustomobject]@{Name='Default-Gateway';Provider='Local'}
    $start=$Clock.ElapsedMilliseconds;$utc=[datetime]::UtcNow
    if($Family -eq 'ICMP'){
        Publish-Probe $target 'ICMP' 'Gateway' $start $utc @{Status='OK';Stage='OK';Ms=0.2;IP='127.0.0.1'}
    }elseif($Family -eq 'DNS'){
        $target.Name='System-Default';$target.Provider='Router'
        Publish-Probe $target 'DNS_UDP' 'RouterDNS' $start $utc @{Status='OK';Stage='OK';Ms=0.3;IP='127.0.0.1';QueryName='fixture.invalid';RCode='NOERROR'}
    }
}
'@
    [IO.File]::AppendAllText((Join-Path $source 'lib/Probes.ps1'),"`n"+$probe)
    $config=Join-Path $source 'Monitor_Config.psd1'
    $text=[IO.File]::ReadAllText($config).Replace("SENSOR_NAME = ''","SENSOR_NAME = 'Integration'").Replace('PreventIdleSleep = $true','PreventIdleSleep = $false').Replace('EnablePushover = $true','EnablePushover = $false')
    $text=$text.Replace('PhaseMs=3050; Enabled=$true','PhaseMs=3050; Enabled=$false').Replace('PhaseMs=3750; Enabled=$true','PhaseMs=3750; Enabled=$false')
    # Test enables just ICMP and DNS. Avoid all native/external adapters.
    $text=[regex]::Replace($text,'(?m)^(\s*(?:TCP443|HTTPS|NIC|TCP_STATS|DNS_TRANSPORT|MTU|TRACE)\s*=.*)Enabled=\$true','$1Enabled=$false')
    [IO.File]::WriteAllText($config,$text,([Text.UTF8Encoding]::new($true)))
    $logRoot=Join-Path $fixture 'Logs';$heartbeat=Join-Path $fixture 'Heartbeat.json';$token='0'*32
    $command='& '+"'"+(Join-Path $source 'Network_Diagnostic_V2_12_RC3.ps1').Replace("'","''")+"'"+' -Diagnostic -DurationSec 7 -NoDashboard -Quiet -LogRoot '+"'"+$logRoot.Replace("'","''")+"'"+' -ControlPath '+"'"+$heartbeat.Replace("'","''")+"'"+' -SupervisorToken '+"'"+$token+"'"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $info=[Diagnostics.ProcessStartInfo]::new($PowerShellPath,('-NoLogo -NoProfile -EncodedCommand '+$encoded));$info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.EnvironmentVariables['COMPUTERNAME']='Integration'
    $child=[Diagnostics.Process]::new();$child.StartInfo=$info;[void]$child.Start();$output=$child.StandardOutput.ReadToEndAsync();$errors=$child.StandardError.ReadToEndAsync()
    if(-not $child.WaitForExit(30000)){$child.Kill();throw 'Coordinator integration exceeded 30 seconds.'}
    if($child.ExitCode -ne 0){throw ('Coordinator fixture failed: '+$output.Result+$errors.Result)}
    Assert-Integration ($child.ExitCode -eq 0) 'Actual coordinator exits normally after bounded healthy run'
    $run=Get-ChildItem -LiteralPath (Join-Path $logRoot 'Integration') -Directory -Filter 'Run_*' | Select-Object -First 1
    Assert-Integration (@(Get-ChildItem -LiteralPath $run.FullName -Recurse -File -Filter '*.csv').Count -eq 0) 'Healthy integrated coordinator creates no probe/Health/Scheduler CSV'
    $summary=[IO.File]::ReadAllText((Join-Path $run.FullName 'Summary_Final.txt'))
    Assert-Integration ($summary -match 'NETWORK: NO_CORROBORATED_FAULT' -and $summary -match 'DNS\s+Started=2 Completed=2' -and $summary -match 'ICMP\s+Started=2 Completed=2') 'Independent probe families finish at their configured cadence'
    $hb=[IO.File]::ReadAllText($heartbeat) | ConvertFrom-Json
    Assert-Integration ($hb.Token -eq $token -and $hb.RunDir -eq $run.FullName -and $hb.ProcessId -eq $child.Id) 'Atomic control heartbeat identifies the actual child and run'
    Assert-Integration ([IO.File]::Exists((Join-Path $run.FullName 'Run_Closed.json'))) 'Actual control loop marks graceful closure'
    $events=Get-ChildItem -LiteralPath $run.FullName -Recurse -Filter 'Events.jsonl' | ForEach-Object{Get-Content -LiteralPath $_.FullName | ForEach-Object{$_ | ConvertFrom-Json}}
    Assert-Integration (@($events | Where-Object{$_.Type -eq 'INCIDENT'}).Count -eq 0) 'Healthy fixture creates zero network incidents'
    $status=[IO.File]::ReadAllText((Join-Path $run.FullName 'Status_Final.json')) | ConvertFrom-Json
    Assert-Integration (($status.monitor.resources.status -in @('OK','PARTIAL')) -and $status.monitor.resources.managedHeapBytes -gt 0 -and ($status.monitor.resources.workingSetBytes -gt 0 -or ($null -eq $status.monitor.resources.workingSetBytes -and 'WorkingSet' -in $status.monitor.resources.unavailableFields)) -and $status.lifecycle -eq 'STOPPED') 'Actual coordinator exports managed heap and explicit unavailable OS counters at closure'
    Assert-Integration ($summary -match 'FAILURE STAGES' -and $summary -match 'ADVISORY TRANSITIONS' -and $summary -match 'NAMED TCP DNS FALLBACKS') 'Final summary retains bounded diagnostics through healthy periods'
    $child.Dispose();$child=$null
    . (Join-Path $PSScriptRoot 'lib/Deployment.ps1')
    # Exercise the real stop/restart ownership action against a separate real child.
    # Only the Process.StartTime adapter is substituted on non-Windows.
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){function Get-ProcessStartIdentity {param([int]$ProcessId=$PID);return 'INTEGRATION_START_ADAPTER'}}
    $command='Start-Sleep -Seconds 30';$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $info=[Diagnostics.ProcessStartInfo]::new($PowerShellPath,('-NoLogo -NoProfile -EncodedCommand '+$encoded));$info.UseShellExecute=$false
    $child=[Diagnostics.Process]::new();$child.StartInfo=$info;[void]$child.Start();$started=Get-ProcessStartIdentity $child.Id
    $progress=New-SupervisorProgress 0L;$hb=[pscustomobject]@{Token='stall';ProcessId=$child.Id;ProcessStartedUTC=$started;MonoMs=1L;Status='RUNNING'}
    [void](Update-SupervisorProgress $progress $hb 'stall' $child.Id $started 1000 2000 2000)
    $decision=Update-SupervisorProgress $progress $hb 'stall' $child.Id $started 3100 2000 2000
    Assert-Integration $decision.Restart 'Independent policy detects a frozen heartbeat from a real child'
    Stop-OwnedMonitor $child $started '' 0
    Assert-Integration $child.HasExited 'Owned stalled child exits before replacement is permitted'
    $oldId=$child.Id;$child.Dispose();$child=$null
    $child=[Diagnostics.Process]::new();$child.StartInfo=$info;[void]$child.Start()
    Assert-Integration (-not $child.HasExited -and $child.Id -ne $oldId) 'A replacement child launches after the previous process exits'
    Stop-OwnedMonitor $child (Get-ProcessStartIdentity $child.Id) '' 0
    Write-Host ('INTEGRATION PASSED: '+$count+' checks; native device/probe adapters are simulated; process start identity is simulated on Linux.')
}finally{
    if($child){try{if(-not $child.HasExited){$child.Kill();[void]$child.WaitForExit(5000)}}catch{};$child.Dispose()}
    if([IO.Directory]::Exists($fixture)){Remove-Item -LiteralPath $fixture -Recurse -Force}
}
