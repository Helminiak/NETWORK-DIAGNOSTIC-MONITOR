. (Join-Path $PSScriptRoot 'Time.ps1')
# Optional delivery adapter. No network IO on the probe/UI thread; no secret keys
# in config snapshots, event logs, the bounded outbox or exported run packages.
function Get-PushoverSecretPath {
    param([string]$Configured='')
    if($Configured){return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Configured)}
    return (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'NetDiag\Pushover_Secrets.clixml')
}

function Assert-PushoverSecretLocation {
    param([string]$Path,[string]$StorageRoot,[string]$ReleaseRoot)
    foreach($root in @($StorageRoot,$ReleaseRoot)){
        if(-not $root){continue}
        $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($root)
        if($Path.Equals($full,[StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($full.TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Store protected Pushover keys outside the release folder and managed log root.'}
    }
}

function Convert-PushoverKeyToText {
    param([Security.SecureString]$Key)
    $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
    try{return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)}
}

function Test-PushoverKeys {
    param($Secrets)
    if(-not $Secrets -or $Secrets.AppToken -isnot [Security.SecureString] -or $Secrets.UserKey -isnot [Security.SecureString]){return $false}
    return ((Convert-PushoverKeyToText $Secrets.AppToken) -cmatch '^[A-Za-z0-9]{30}$' -and (Convert-PushoverKeyToText $Secrets.UserKey) -cmatch '^[A-Za-z0-9]{30}$')
}

function Get-AlertNow { return [datetime]::UtcNow }

function Initialize-Notifications {
    param([switch]$SkipCredentials)
    $script:Alerts=[pscustomobject]@{Ready=$false;Mode='DISABLED';Secrets=$null;Pending=[Collections.Generic.List[object]]::new();SentTimes=[Collections.Generic.List[datetime]]::new();FaultTimes=@{};Episode=$null;Worker=$null;Delivered=0L;Failed=0L;Dropped=0L;LastStatus='';StatePath=$null;StateWritable=$true;TransportScript=''}
    if(-not $script:Cfg.EnablePushover){return}
    $script:Alerts.Mode='NOT_CONFIGURED'
    if($SkipCredentials){return}
    try{
        $path=Get-PushoverSecretPath $script:Cfg.PushoverSecretPath
        Assert-PushoverSecretLocation $path $script:Cfg.RootDir (Split-Path $PSScriptRoot -Parent)
        if(-not [IO.File]::Exists($path)){return}
        $secrets=Import-Clixml -LiteralPath $path -ErrorAction Stop
        if(-not (Test-PushoverKeys $secrets)){throw 'Invalid protected keys.'}
        $script:Alerts.Secrets=$secrets;$script:Alerts.Ready=$true;$script:Alerts.Mode='ARMED'
    }catch{$script:Alerts.Mode='CONFIG_ERROR';$script:Alerts.LastStatus='Protected keys cannot be loaded under this Windows account; run SETUP_PUSHOVER.bat.'}
}

function Connect-NotificationStorage {
    $a=$script:Alerts;if(-not $a){return}
    $a.StatePath=Join-Path $script:SensorRoot 'Alert_State.json'
    if(-not [IO.File]::Exists($a.StatePath)){return}
    try{
        $file=Get-Item -LiteralPath $a.StatePath
        if($file.Length -gt 256KB){throw 'Oversized alert state.'}
        $state=[IO.File]::ReadAllText($a.StatePath) | ConvertFrom-Json
        if($state.SensorName -ne $script:Cfg.SENSOR_NAME -or $state.SchemaVersion -ne 1){throw 'Alert state identity/schema mismatch.'}
        $now=Get-AlertNow
        foreach($item in @($state.Pending)){
            if(-not $item -or $a.Pending.Count -ge $script:Cfg.AlertMaxPending){continue}
            if($item.Message.Length -gt 900 -or $item.Title.Length -gt 200){throw 'Invalid alert payload size.'}
            if($item.Id -notmatch '^[a-f0-9]{32}$' -or $item.Type -notin @('INCIDENT','INCIDENT_RECOVERED','RECOVERY','FATAL','RECORDER_LIMIT','STORAGE_WARNING','CAPTURE_FAILED','SENSOR_GAP') -or $item.Priority -notin @(-1,0,1) -or $item.Attempts -lt 0){throw 'Invalid alert state item.'}
            [void][datetime]::Parse($item.CreatedUTC);[void][datetime]::Parse($item.NextAttemptUTC)
            if((Convert-MonitorUtc $item.ExpiresUTC) -le $now){$a.Dropped++;continue}
            $a.Pending.Add($item)
        }
        if(@($state.SentTimesUTC).Count -gt 60){throw 'Invalid alert rate history.'}
        foreach($time in @($state.SentTimesUTC)){if($time){$t=(Convert-MonitorUtc $time);if($t -gt $now.AddHours(-1)){$a.SentTimes.Add($t)}}}
        if($state.FaultTimes){foreach($p in $state.FaultTimes.PSObject.Properties){if($p.Name -in $script:Cfg.AlertFaultTypes){$a.FaultTimes[$p.Name]=(Convert-MonitorUtc $p.Value)}}}
        # A process restart cannot establish recovery of the previous episode.
        # Its queued onset remains deliverable, but does not gate this run's faults.
    }catch{$a.Pending.Clear();$a.StateWritable=$false;$a.LastStatus='Saved alert outbox is unreadable; inspect Alert_State.json before replacing it.';if($a.Ready){$a.Mode='STATE_ERROR';$a.Ready=$false}}
}

function Save-NotificationState {
    $a=$script:Alerts;if(-not $a -or -not $a.StatePath -or -not $a.StateWritable -or -not $script:Storage){return}
    if(-not $a.Ready -and -not $a.Pending.Count -and -not $a.SentTimes.Count -and -not $a.FaultTimes.Count){return}
    $record=@{SchemaVersion=1;SensorName=$script:Cfg.SENSOR_NAME;SensorRole=$script:Cfg.SENSOR_ROLE;UpdatedUTC=(Get-AlertNow).ToString('o');Pending=@($a.Pending);SentTimesUTC=@($a.SentTimes | ForEach-Object{$_.ToString('o')});FaultTimes=@{}}
    foreach($key in $a.FaultTimes.Keys){$record.FaultTimes[$key]=$a.FaultTimes[$key].ToString('o')}
    $text=$record | ConvertTo-Json -Depth 6
    if([Text.Encoding]::UTF8.GetByteCount($text) -gt 256KB){$a.LastStatus='Alert outbox size limit reached.';return}
    try{if(-not (Write-ManagedText $a.StatePath $text -Critical -Final)){$a.LastStatus='Alert outbox could not be saved within quota; unsent items remain in bounded RAM.'}}catch{$a.LastStatus='Alert outbox write failed; unsent items remain in bounded RAM.'}
}

function Add-Notification {
    param([string]$Type,[string]$Code,[string]$Message,[string]$EpisodeId='',[int]$DelaySec=0,[int]$Priority=0)
    $a=$script:Alerts;if(-not $a -or -not $a.Ready){return $null}
    # One outstanding notification of each episode/type. Retries reuse its ID.
    $existing=$a.Pending | Where-Object{$_.Type -eq $Type -and $_.EpisodeId -eq $EpisodeId -and $_.Code -eq $Code} | Select-Object -First 1
    if($existing){return $existing}
    if($a.Pending.Count -ge $script:Cfg.AlertMaxPending){
        if($Type -eq 'FATAL'){$old=$a.Pending | Where-Object{$_.Type -ne 'FATAL'} | Select-Object -First 1;if($old){[void]$a.Pending.Remove($old)}else{$a.Dropped++;return $null}}else{$a.Dropped++;return $null}
        $a.Dropped++
    }
    $now=Get-AlertNow;$id=[guid]::NewGuid().ToString('N')
    $body='Sensor='+$script:Cfg.SENSOR_NAME+' Role='+$script:Cfg.SENSOR_ROLE+' Run='+$script:RunId+"`nUTC="+$now.ToString('o')+"`n"+$Message+"`nAlert="+$id.Substring(0,8)
    if($body.Length -gt 900){$body=$body.Substring(0,897)+'...'}
    $title='NetDiag '+$script:Cfg.SENSOR_NAME+': '+$Type+' '+$Code;if($title.Length -gt 200){$title=$title.Substring(0,200)}
    $item=[pscustomobject]@{Id=$id;Type=$Type;Code=$Code;EpisodeId=$EpisodeId;Title=$title;Message=$body;CreatedUTC=$now.ToString('o');NextAttemptUTC=$now.AddSeconds($DelaySec).ToString('o');ExpiresUTC=$now.AddHours($script:Cfg.AlertExpiryHours).ToString('o');Priority=$Priority;Attempts=0}
    $a.Pending.Add($item);Save-NotificationState;return $item
}

function Receive-NotificationEvent {
    param([string]$Type,[string]$Message,$Assessment=$null)
    $a=$script:Alerts;if(-not $a -or -not $a.Ready){return}
    $now=Get-AlertNow
    if($Type -eq 'INCIDENT' -and $Assessment -and $Assessment.IncidentEligible -and $Assessment.Corroborated){
        if($a.Episode -and -not $a.Episode.Recovered){return} # reclassification within a continuing fault is not a new page
        $id=$script:State.EpisodeId
        $a.Episode=[pscustomobject]@{Id=$id;Code=$Assessment.Code;StartedUTC=$now;Sent=$false;Recovered=$false;RecoveryUTC=$null}
        [void](Add-Notification 'INCIDENT' $Assessment.Code ($Message+"`nProtocols="+($Assessment.Protocols -join ',')+' Providers='+($Assessment.Providers -join ',')) $id $script:Cfg.AlertIncidentDelaySec $script:Cfg.AlertIncidentPriority)
        return
    }
    if($Type -eq 'RECOVERY' -and $a.Episode){
        $episode=$a.Episode;$episode.Recovered=$true;$episode.RecoveryUTC=$now;$duration=($now-$episode.StartedUTC).TotalSeconds
        $pending=$a.Pending | Where-Object{$_.EpisodeId -eq $episode.Id -and $_.Type -eq 'INCIDENT'} | Select-Object -First 1
        if($duration -lt $script:Cfg.AlertIncidentDelaySec -and -not $episode.Sent -and -not ($a.Worker -and $a.Worker.Item.EpisodeId -eq $episode.Id)){
            if($pending){[void]$a.Pending.Remove($pending)}
        }elseif($pending -and -not ($a.Worker -and $a.Worker.Item.Id -eq $pending.Id)){
            $pending.Type='INCIDENT_RECOVERED';$pending.Title='NetDiag '+$script:Cfg.SENSOR_NAME+': INCIDENT RECOVERED';$pending.Message=$pending.Message.Substring(0,[math]::Min(740,$pending.Message.Length))+"`nRecovered UTC="+$now.ToString('o')+'; duration='+[math]::Round($duration)+' seconds. Delivery was deferred.';$pending.NextAttemptUTC=$now.ToString('o')
        }elseif($episode.Sent -and $script:Cfg.AlertOnRecovery){
            [void](Add-Notification 'RECOVERY' $episode.Code ($Message+' Duration='+[math]::Round($duration)+' seconds.') $episode.Id 0 $script:Cfg.AlertRecoveryPriority)
        }
        # Keep a recovered episode until an in-flight onset finishes, so its
        # completion can add exactly one recovery (or merge a failed onset).
        if(-not ($a.Worker -and $a.Worker.Item.EpisodeId -eq $episode.Id)){$a.Episode=$null}
        Save-NotificationState;return
    }
    if($Type -in $script:Cfg.AlertFaultTypes){
        if($Type -ne 'FATAL' -and $a.FaultTimes.ContainsKey($Type) -and ($now-$a.FaultTimes[$Type]).TotalSeconds -lt $script:Cfg.AlertFaultCooldownSec){return}
        $a.FaultTimes[$Type]=$now
        [void](Add-Notification $Type 'MONITOR_HEALTH' $Message '' 0 $script:Cfg.AlertIncidentPriority)
    }
}

function Get-PushoverEncodedPayload {
    param($Item,$Secrets,[string]$Device)
    $fields=@{token=(Convert-PushoverKeyToText $Secrets.AppToken);user=(Convert-PushoverKeyToText $Secrets.UserKey);title=$Item.Title;message=$Item.Message;priority=[string]$Item.Priority;timestamp=[string]([long]((Convert-MonitorUtc $Item.CreatedUTC)-[datetime]'1970-01-01').TotalSeconds)}
    if($Device){$fields.device=$Device}
    return (@(foreach($key in $fields.Keys){[uri]::EscapeDataString($key)+'='+[uri]::EscapeDataString([string]$fields[$key])}) -join '&')
}

function Invoke-PushoverDelivery {
    param($Item,$Secrets,[string]$Device,[int]$TimeoutSec)
    Add-Type -AssemblyName System.Net.Http
    $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false
    $client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds($TimeoutSec);$client.MaxResponseContentBufferSize=16384
    $content=$null;$response=$null
    try{
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        $encoded=Get-PushoverEncodedPayload $Item $Secrets $Device
        $content=[Net.Http.StringContent]::new($encoded,[Text.Encoding]::UTF8,'application/x-www-form-urlencoded')
        $task=$client.PostAsync('https://api.pushover.net/1/messages.json',$content)
        if(-not $task.Wait($TimeoutSec*1000)){$client.CancelPendingRequests();return @{Succeeded=$false;Retryable=$true;StatusCode=0;FailureCode='TIMEOUT';RetryAfterSec=0}}
        $response=$task.Result;$code=[int]$response.StatusCode
        if($code -eq 200){$body=$response.Content.ReadAsStringAsync().Result | ConvertFrom-Json;if($body.status -eq 1){return @{Succeeded=$true;Retryable=$false;StatusCode=$code;FailureCode='';RetryAfterSec=0}}}
        $delay=0
        if($code -eq 429){
            $delay=900
            if($response.Headers.Contains('X-Limit-App-Reset')){$reset=[long]($response.Headers.GetValues('X-Limit-App-Reset') | Select-Object -First 1);$delay=[math]::Max($delay,($reset-([long]([datetime]::UtcNow-[datetime]'1970-01-01').TotalSeconds)))}
        }
        return @{Succeeded=$false;Retryable=($code -eq 429 -or $code -ge 500);StatusCode=$code;FailureCode=('HTTP_'+$code);RetryAfterSec=$delay}
    }catch{return @{Succeeded=$false;Retryable=$true;StatusCode=0;FailureCode='TRANSPORT_ERROR';RetryAfterSec=0}}
    finally{if($response){$response.Dispose()};if($content){$content.Dispose()};$client.Dispose();$handler.Dispose()}
}

function Write-NotificationResult {
    param([string]$Message,[string]$Type)
    if($script:RunDir -and $script:Storage -and $script:Clock -and $null -ne $script:RecentHistory){Write-EventLog $Message $Type}
}

function Step-Notifications {
    $a=$script:Alerts;if(-not $a -or -not $a.Ready){return}
    $now=Get-AlertNow
    if($a.Worker -and $a.Worker.Handle.IsCompleted){
        $worker=$a.Worker;$item=$worker.Item
        try{$result=@($worker.PowerShell.EndInvoke($worker.Handle)) | Select-Object -Last 1;if(-not $result -or $worker.PowerShell.Streams.Error.Count){$result=@{Succeeded=$false;Retryable=$true;StatusCode=0;FailureCode='WORKER_ERROR';RetryAfterSec=0}}}catch{$result=@{Succeeded=$false;Retryable=$true;StatusCode=0;FailureCode='WORKER_ERROR';RetryAfterSec=0}}finally{$worker.PowerShell.Dispose();$a.Worker=$null}
        if($result.Succeeded){
            [void]$a.Pending.Remove($item);$a.SentTimes.Add($now);$a.Delivered++;$a.Mode='ARMED';$a.LastStatus='Pushover accepted '+$item.Type+' '+$item.Id.Substring(0,8)
            if($worker.Episode){
                $worker.Episode.Sent=$true
                if($worker.Episode.Recovered){
                    if($script:Cfg.AlertOnRecovery){[void](Add-Notification 'RECOVERY' $worker.Episode.Code ('Recovered UTC='+$worker.Episode.RecoveryUTC.ToString('o')) $worker.Episode.Id 0 $script:Cfg.AlertRecoveryPriority)}
                    if($a.Episode -and $a.Episode.Id -eq $worker.Episode.Id){$a.Episode=$null}
                }
            }
            Write-NotificationResult $a.LastStatus 'NOTIFICATION_ACCEPTED'
        }else{
            $a.Failed++;$a.LastStatus='Delivery deferred: '+$result.FailureCode+'; alert='+$item.Id.Substring(0,8);$a.Mode='DEFERRED'
            if(-not $result.Retryable){$a.Ready=$false;$a.Mode='CONFIG_ERROR';$a.LastStatus='Pushover rejected request ('+$result.FailureCode+'); check setup. Pending alerts retained.'}
            $delay=[math]::Min($script:Cfg.AlertRetryMaxSec,$script:Cfg.AlertRetryInitialSec*[math]::Pow(2,[math]::Min(20,$item.Attempts-1)));$delay=[math]::Max($delay,$result.RetryAfterSec);$item.NextAttemptUTC=$now.AddSeconds($delay).ToString('o')
            if($worker.Episode -and $worker.Episode.Recovered){$item.Type='INCIDENT_RECOVERED';$item.Title='NetDiag '+$script:Cfg.SENSOR_NAME+': INCIDENT RECOVERED';$item.Message=$item.Message.Substring(0,[math]::Min(740,$item.Message.Length))+"`nRecovered UTC="+$worker.Episode.RecoveryUTC.ToString('o')+'; onset delivery was deferred.';if($a.Episode -and $a.Episode.Id -eq $worker.Episode.Id){$a.Episode=$null}}
            if($item.Attempts -eq 1 -or -not $result.Retryable){Write-NotificationResult $a.LastStatus 'NOTIFICATION_WARNING'}
        }
        Save-NotificationState
    }
    if(-not $a.Ready -or $a.Worker){return}
    $dirty=$false
    foreach($item in @($a.Pending)){if((Convert-MonitorUtc $item.ExpiresUTC) -le $now){[void]$a.Pending.Remove($item);$a.Dropped++;$dirty=$true}}
    foreach($t in @($a.SentTimes)){if($t -le $now.AddHours(-1)){[void]$a.SentTimes.Remove($t);$dirty=$true}}
    if($dirty){Save-NotificationState}
    if($a.SentTimes.Count -ge $script:Cfg.AlertMaxPerHour){$a.Mode='RATE_LIMITED';return}
    if($a.Mode -eq 'RATE_LIMITED' -or -not $a.Pending.Count){$a.Mode='ARMED'}
    if($a.SentTimes.Count -and ($now-($a.SentTimes | Sort-Object -Descending | Select-Object -First 1)).TotalSeconds -lt $script:Cfg.AlertCooldownSec){return}
    $item=$a.Pending | Where-Object{(Convert-MonitorUtc $_.NextAttemptUTC) -le $now} | Sort-Object @{Expression={if($_.Type -eq 'FATAL'){0}else{1}}},CreatedUTC | Select-Object -First 1
    if(-not $item){return}
    $item.Attempts++
    # Persist before sending. A crash/ambiguous timeout can duplicate a notification;
    # the stable Alert ID identifies it. Pushover provides no idempotency key.
    Save-NotificationState
    $ps=[powershell]::Create();$worker='param($Path,$Item,$Secrets,$Device,$Timeout); . $Path; Invoke-PushoverDelivery $Item $Secrets $Device $Timeout'
    if($a.TransportScript){$worker=$a.TransportScript}
    [void]$ps.AddScript($worker).AddArgument((Join-Path $PSScriptRoot 'Notifications.ps1')).AddArgument($item).AddArgument($a.Secrets).AddArgument($script:Cfg.PushoverDevice).AddArgument($script:Cfg.AlertRequestTimeoutSec)
    $episode=if($a.Episode -and $a.Episode.Id -eq $item.EpisodeId){$a.Episode}else{$null}
    $a.Worker=[pscustomobject]@{PowerShell=$ps;Handle=$ps.BeginInvoke();Item=$item;Episode=$episode};$a.Mode='SENDING'
}

function Stop-Notifications {
    $a=$script:Alerts;if(-not $a){return}
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do{Step-Notifications;if(-not $a.Worker){break};Start-Sleep -Milliseconds 25}while($timer.Elapsed.TotalSeconds -lt $script:Cfg.AlertShutdownWaitSec)
    # Do not call PowerShell.Stop on a blocked HTTP/DNS thread from the UI thread.
    # The bounded request finishes in its own worker; unsent state survives exit.
    if($a.Worker){$a.LastStatus='Shutdown: pending notification retained for next launch.'}
    Save-NotificationState
}
