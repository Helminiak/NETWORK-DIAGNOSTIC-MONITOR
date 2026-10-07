# Storage adapter only. Probe, classifier and dashboard state stay in Runtime/Core.
function Assert-StoragePath {
    param([string]$Path)
    $full=[IO.Path]::GetFullPath($Path);$root=[IO.Path]::GetFullPath($script:SensorRoot).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    if(-not $full.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw ('Storage path outside sensor root: '+$full)}
    $parent=$full
    while($parent -and $parent.Length -ge $root.Length){
        if(Test-Path -LiteralPath $parent){if(([IO.File]::GetAttributes($parent) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse points are not allowed in managed storage: '+$parent)}}
        $parent=[IO.Path]::GetDirectoryName($parent)
    }
    return $full
}

function Remove-ManagedItem {
    param([string]$Path)
    $full=Assert-StoragePath $Path
    if(Test-Path -LiteralPath $full){
        foreach($item in Get-ChildItem -LiteralPath $full -Recurse -Force -ErrorAction Stop){[void](Assert-StoragePath $item.FullName)}
        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    }
}

function Initialize-Storage {
    $script:SensorRoot=Join-Path $Cfg.RootDir $Cfg.SENSOR_NAME
    [void][IO.Directory]::CreateDirectory($SensorRoot)
    [void](Assert-StoragePath (Join-Path $SensorRoot '.sensor.lock'))
    $script:StorageLock=[IO.File]::Open((Join-Path $SensorRoot '.sensor.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $owner=Join-Path $SensorRoot 'Storage_Owner.json'
    if([IO.File]::Exists($owner)){
        $identity=[IO.File]::ReadAllText($owner) | ConvertFrom-Json
        if($identity.SensorName -ne $Cfg.SENSOR_NAME -or $identity.StorageSchema -ne 1){throw 'Storage owner mismatch; choose a new RootDir.'}
    }else{
        $existing=@(Get-ChildItem -LiteralPath $SensorRoot -Force | Where-Object{$_.Name -ne '.sensor.lock'})
        if($existing.Count){throw 'Sensor storage is not empty and has no ownership marker; choose a new RootDir.'}
        [IO.File]::WriteAllText($owner,(@{StorageSchema=1;SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE} | ConvertTo-Json))
    }
    $script:Storage=[pscustomobject]@{Quota=[long]($Cfg.StorageQuotaGB*1GB);Reserve=[long]($Cfg.StorageReserveMB*1MB);Used=0L;Reservations=@{};Dropped=0L;LastPruneMs=-1000L;NextMaintenanceMs=0L;Compression=$null;Pruned=0L}
    $script:Recorder=$null;$script:Ring=[Collections.Generic.Queue[object]]::new();$script:RingBytes=0L;$script:RingEvicted=0L;$script:RingExpired=0L;$script:RingCapacityEvicted=0L
    # The exclusive lock proves old runs have no coordinator. Never silently treat
    # interrupted evidence as a normally recovered incident.
    foreach($run in Get-ChildItem -LiteralPath $SensorRoot -Directory -Filter 'Run_*'){
        foreach($partial in Get-ChildItem -LiteralPath (Join-Path $run.FullName 'Incidents') -Filter '*.zip.partial' -File -ErrorAction SilentlyContinue){
            $source=$partial.FullName.Substring(0,$partial.FullName.Length-12)
            if([IO.File]::Exists((Join-Path $source 'Closed.json'))){Remove-ManagedItem $partial.FullName}
        }
        foreach($capture in Get-ChildItem -LiteralPath (Join-Path $run.FullName 'PacketCaptures') -Filter '*.etl' -File -ErrorAction SilentlyContinue){
            $manifest=$capture.FullName+'.capture.json';$status=$capture.FullName+'.status.txt'
            if([IO.File]::Exists($manifest) -and (-not [IO.File]::Exists($status) -or [IO.File]::ReadAllText($status) -notmatch 'StopExit=0\b')){
                # A hard-killed coordinator can leave a native circular session.
                # Reserve its entire native cap and protect it from pruning.
                $m=[IO.File]::ReadAllText($manifest) | ConvertFrom-Json
                if($m.MaxMB -lt 1 -or $m.MaxMB -gt 1024){throw ('Invalid native capture reservation: '+$manifest)}
                if($m.SensorName -eq $Cfg.SENSOR_NAME){$Storage.Reservations[$capture.FullName]=[pscustomobject]@{Path=$capture.FullName;Bytes=[long]($m.MaxMB*1MB+1MB)}}
            }
        }
    }
    Update-StorageUsage
    foreach($run in Get-ChildItem -LiteralPath $SensorRoot -Directory -Filter 'Run_*'){
        foreach($active in Get-ChildItem -LiteralPath (Join-Path $run.FullName 'Incidents') -Filter 'Active.json' -Recurse -ErrorAction SilentlyContinue){
            [void](Assert-StoragePath $active.FullName)
            $closed=Join-Path $active.DirectoryName 'Closed.json'
            $original=[IO.File]::ReadAllText($active.FullName) | ConvertFrom-Json
            $role=if($original.SensorRole){$original.SensorRole}else{$Cfg.SENSOR_ROLE}
            if(-not [IO.File]::Exists($closed)){if(-not (Write-ManagedText $closed (@{SensorName=$Cfg.SENSOR_NAME;SensorRole=$role;ClosedUTC=[datetime]::UtcNow.ToString('o');Reason='INTERRUPTED_PREVIOUS_PROCESS';Recovered=$false} | ConvertTo-Json) -Critical -Final)){continue}}
            [IO.File]::Delete($active.FullName)
        }
        $marker=Join-Path $run.FullName 'Run_Closed.json'
        if(-not [IO.File]::Exists($marker)){[void](Write-ManagedText $marker (@{SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;ClosedUTC=[datetime]::UtcNow.ToString('o');Reason='INTERRUPTED_PREVIOUS_PROCESS'} | ConvertTo-Json) -Critical -Final)}
    }
    Update-StorageUsage
    Invoke-StorageMaintenance -NeedBytes $Storage.Reserve
    if($Storage.Used+$Storage.Reserve -gt $Storage.Quota){throw 'Sensor quota is occupied by protected/unrecognized files. Increase quota or archive those files manually.'}
}

function Update-StorageUsage {
    $bytes=0L
    foreach($file in Get-ChildItem -LiteralPath $SensorRoot -File -Recurse -Force){
        [void](Assert-StoragePath $file.FullName)
        if($file.Name -eq '.sensor.lock'){continue}
        $covered=$false
        foreach($r in $Storage.Reservations.Values){if($file.FullName -eq $r.Path -or $file.FullName.StartsWith($r.Path+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){$covered=$true;break}}
        if(-not $covered){
            # Windows directory enumeration can report a stale length while an
            # append handle is open. Account directly from our open streams.
            $length=$null
            foreach($name in $script:LogPaths.Keys){if($script:LogPaths[$name] -eq $file.FullName -and $Writers[$name]){$length=$Writers[$name].BaseStream.Length;break}}
            if($null -eq $length -and $Recorder -and $file.DirectoryName -eq $Recorder.Path -and $Recorder.Writers[$file.Name]){$length=$Recorder.Writers[$file.Name].BaseStream.Length}
            if($null -eq $length){$file.Refresh();$length=$file.Length}
            $bytes+=$length
        }
    }
    foreach($r in $Storage.Reservations.Values){$bytes+=$r.Bytes}
    $Storage.Used=$bytes
}

function Request-StorageSpace {
    param([long]$Bytes,[switch]$Critical,[switch]$Final)
    $margin=if($Final){0}elseif($Critical){1MB}else{$Storage.Reserve}
    $limit=$Storage.Quota-$margin
    if($Storage.Used+$Bytes -gt $limit -and $Clock -and $Clock.ElapsedMilliseconds-$Storage.LastPruneMs -ge 1000){
        $Storage.LastPruneMs=$Clock.ElapsedMilliseconds
        Invoke-StorageMaintenance -NeedBytes ($Bytes+$margin)
    }
    return ($Storage.Used+$Bytes -le $limit)
}

function Write-ManagedText {
    param([string]$Path,[string]$Text,[switch]$Critical,[switch]$Final)
    $full=Assert-StoragePath $Path;$bytes=[Text.Encoding]::UTF8.GetByteCount($Text)+3
    # Atomic replacement temporarily needs both old and new file allocations.
    if(-not (Request-StorageSpace $bytes -Critical:$Critical -Final:$Final)){$Storage.Dropped++;return $false}
    $old=if([IO.File]::Exists($full)){([IO.FileInfo]$full).Length}else{0L}
    Write-AtomicText $full $Text;$Storage.Used+=$bytes-$old
    return $true
}

function Reserve-Storage {
    param([string]$Path,[long]$Bytes)
    $full=Assert-StoragePath $Path
    if(-not (Request-StorageSpace $Bytes)){return $false}
    $Storage.Reservations[$full]=[pscustomobject]@{Path=$full;Bytes=$Bytes};$Storage.Used+=$Bytes
    return $true
}

function Release-StorageReservation {
    param([string]$Path)
    if($Path.EndsWith('.etl',[StringComparison]::OrdinalIgnoreCase) -and [IO.File]::Exists($Path)){
        $status=$Path+'.status.txt'
        if(-not [IO.File]::Exists($status) -or [IO.File]::ReadAllText($status) -notmatch 'StopExit=0\b'){Update-StorageUsage;return}
    }
    [void]$Storage.Reservations.Remove($Path);Update-StorageUsage
}

function Close-RunLogWriters {
    foreach($writer in $Writers.Values){$writer.Dispose()};$script:Writers=@{};$script:CsvHeaders=@{};$script:LogPaths=@{}
}

function Get-RunLogPath {
    param([string]$Name)
    $day=[datetime]::UtcNow.ToString('yyyyMMdd');$current=$script:LogPaths[$Name]
    if($current -and [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($current)) -eq $day -and $Writers[$Name].BaseStream.Length -lt $Cfg.NormalLogMaxMB*1MB){return $current}
    if($Writers[$Name]){$Writers[$Name].Dispose();$Writers.Remove($Name);$CsvHeaders.Remove($Name)}
    $folder=Join-Path $RunDir ('Logs\'+$day);[void][IO.Directory]::CreateDirectory($folder)
    $path=Join-Path $folder $Name
    if([IO.File]::Exists($path)){$path=Join-Path $folder ([IO.Path]::GetFileNameWithoutExtension($Name)+'_'+[guid]::NewGuid().ToString('N').Substring(0,8)+[IO.Path]::GetExtension($Name))}
    $script:LogPaths[$Name]=$path
    return $path
}

function Write-RunLogLine {
    param([string]$Name,[string]$Line,[string]$Header='')
    $path=Get-RunLogPath $Name;$prefix=if($Header -and -not $CsvHeaders[$Name]){$Header+"`r`n"}else{''}
    $text=$prefix+$Line+"`r`n";$bytes=[Text.Encoding]::UTF8.GetByteCount($text)+$(if($Writers[$Name]){0}else{3})
    if(-not (Request-StorageSpace $bytes -Critical)){$Storage.Dropped++;return}
    if(-not $Writers[$Name]){$writer=[IO.StreamWriter]::new($path,$true,([Text.UTF8Encoding]::new($true)));$writer.AutoFlush=$true;$Writers[$Name]=$writer}
    $Writers[$Name].Write($text);if($Header){$CsvHeaders[$Name]=$true};$Storage.Used+=$bytes
}

function Add-RingTelemetry {
    param($Record,$Legacy,[string]$File)
    $now=$Clock.ElapsedMilliseconds;$cutoff=$now-$Cfg.RingBufferMinutes*60000
    # Queue order is receipt order; completion can arrive out of order across families.
    while($Ring.Count -and $Ring.Peek().ReceiptMs -lt $cutoff){$old=$Ring.Dequeue();$script:RingBytes-=$old.Bytes;$script:RingEvicted++;$script:RingExpired++}
    $entry=[pscustomobject]@{Record=$Record;Legacy=$Legacy;File=$File;ReceiptMs=$now;Bytes=([Text.Encoding]::UTF8.GetByteCount($Record.DataJSON)+2048)}
    if($Record.EndMonoMs -ge $cutoff){$Ring.Enqueue($entry);$script:RingBytes+=$entry.Bytes}
    while($Ring.Count -gt $Cfg.RingBufferMaxRecords -or $RingBytes -gt $Cfg.RingBufferMaxMB*1MB){$old=$Ring.Dequeue();$script:RingBytes-=$old.Bytes;$script:RingEvicted++;$script:RingCapacityEvicted++}
    if($script:Recorder){Write-IncidentTelemetry $entry $(if($null -ne $Recorder.RecoveryMs){'PostEvent'}else{'Event'})}
}

function Write-IncidentTelemetry {
    param($Entry,[string]$Phase)
    if(-not $Recorder){return}
    # Ignore observations that completed beyond the requested post window, even
    # if the coordinator has not yet processed its close deadline.
    if($null -ne $Recorder.CloseMs -and $Entry.Record.EndMonoMs -gt $Recorder.CloseMs){return}
    $record=[ordered]@{};foreach($p in $Entry.Record.PSObject.Properties){$record[$p.Name]=$p.Value};$record.RecordingPhase=$Phase
    $items=@(@{File=$Phase+'.csv';Record=[pscustomobject]$record})
    if($Entry.File -and $Entry.File -ne 'Route_Changes.log'){$legacy=[ordered]@{};foreach($p in $Entry.Legacy.PSObject.Properties){$legacy[$p.Name]=$p.Value};$legacy.RecordingPhase=$Phase;$items+=@{File=$Entry.File;Record=[pscustomobject]$legacy}}
    if($Entry.Record.Protocol -eq 'TRACE'){
        $trace=$Entry.Record.DataJSON | ConvertFrom-Json
        $items+=@{File='Trace.csv';Record=[pscustomobject]@{TimestampUTC=$Entry.Record.TimestampUTC;Name=$Entry.Record.Name;Stage=$Entry.Record.Stage;Signature=$trace.Signature;Text=$trace.Text;RecordingPhase=$Phase}}
    }
    foreach($item in $items){
        $csv=@($item.Record | ConvertTo-Csv -NoTypeInformation);$path=Join-Path $Recorder.Path $item.File
        $text=$(if(-not $Recorder.Headers[$item.File]){$csv[0]+"`r`n"}else{''})+$csv[1]+"`r`n"
        $bytes=[Text.Encoding]::UTF8.GetByteCount($text)+$(if($Recorder.Writers[$item.File]){0}else{3})
        if($Recorder.Bytes+$bytes -gt $Cfg.IncidentTelemetryMaxMB*1MB -or -not (Request-StorageSpace $bytes)){
            $Recorder.Dropped++
            if(-not $Recorder.LimitReported){$Recorder.LimitReported=$true;Write-EventLog ('Incident detail limit/quota reached: '+$Recorder.Path+'. RAM probes, UI, state events and summaries continue; see dropped-row counts.') 'RECORDER_LIMIT'}
            if($item.File -eq $Phase+'.csv'){return}
            continue
        }
        if(-not $Recorder.Writers[$item.File]){$w=[IO.StreamWriter]::new($path,$true,([Text.UTF8Encoding]::new($true)));$w.AutoFlush=$true;$Recorder.Writers[$item.File]=$w}
        $Recorder.Writers[$item.File].Write($text);$Recorder.Headers[$item.File]=$true;$Recorder.Bytes+=$bytes;$Storage.Used+=$bytes
    }
}

function Start-IncidentRecorder {
    param($Assessment)
    if($Recorder){$Recorder.RecoveryMs=$null;$Recorder.CloseMs=$null;$Recorder.Episodes.Add($State.EpisodeId);return $Recorder.Path}
    $path=Join-Path $IncidentRoot ([datetime]::UtcNow.ToString('yyyyMMdd_HHmmss')+'_'+$State.EpisodeId+'_'+$Assessment.Code)
    [void][IO.Directory]::CreateDirectory($path)
    $script:Recorder=[pscustomobject]@{Path=$path;StartedMs=$Clock.ElapsedMilliseconds;RecoveryMs=$null;CloseMs=$null;Writers=@{};Headers=@{};Bytes=0L;Dropped=0L;LimitReported=$false;Episodes=[Collections.Generic.List[string]]::new()}
    $Recorder.Episodes.Add($State.EpisodeId)
    [void](Write-ManagedText (Join-Path $path 'Active.json') (@{SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;EpisodeId=$State.EpisodeId;StartedUTC=[datetime]::UtcNow.ToString('o')} | ConvertTo-Json) -Critical)
    $cutoff=$Clock.ElapsedMilliseconds-$Cfg.IncidentPreMinutes*60000
    foreach($entry in $Ring){if($entry.Record.EndMonoMs -ge $cutoff){Write-IncidentTelemetry $entry 'PreEvent'}}
    return $path
}

function Set-IncidentRecovery {
    if($Recorder){$Recorder.RecoveryMs=$Clock.ElapsedMilliseconds;$Recorder.CloseMs=$Recorder.RecoveryMs+$Cfg.IncidentPostMinutes*60000}
}

function Close-IncidentRecorder {
    param([string]$Reason='POST_WINDOW_COMPLETE')
    if(-not $Recorder){return}
    foreach($w in $Recorder.Writers.Values){$w.Dispose()}
    $meta=@{SchemaVersion=1;SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;EpisodeIds=@($Recorder.Episodes);ClosedUTC=[datetime]::UtcNow.ToString('o');Reason=$Reason;Recovered=($null -ne $Recorder.RecoveryMs);StartedMonoMs=$Recorder.StartedMs;RecoveryMonoMs=$Recorder.RecoveryMs;PostDeadlineMonoMs=$Recorder.CloseMs;TelemetryBytes=$Recorder.Bytes;DroppedRecords=$Recorder.Dropped;RingEvicted=$RingEvicted;RingExpired=$script:RingExpired;RingCapacityEvicted=$script:RingCapacityEvicted}
    $path=$Recorder.Path
    if(Write-ManagedText (Join-Path $path 'Closed.json') ($meta | ConvertTo-Json -Depth 4) -Critical){[IO.File]::Delete((Join-Path $path 'Active.json'))}
    $script:Recorder=$null;Update-StorageUsage
    Write-EventLog ('Closed incident '+$path+'; '+$Reason+'; dropped CSV rows='+$meta.DroppedRecords) 'RECORDER_CLOSED'
}

function Write-HealthySummary {
    $utc=[datetime]::UtcNow;$pings=@($PingStats.Values);$dns=@($DnsStats.Values);$tcp=@($TcpConnectStats.Values);$https=@($HttpsStats.Values)
    $record=[pscustomobject][ordered]@{SchemaVersion=1;TimestampUTC=$utc.ToString('o');Timestamp=$utc.ToLocalTime().ToString('o');SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;MonoMs=$Clock.ElapsedMilliseconds;Assessment=$Assessment.Code;ActiveIncident=$State.Active;Gateway=$RouteInfo.Gateway;PingSent=($pings | Measure-Object Sent -Sum).Sum;PingLost=($pings | Measure-Object Lost -Sum).Sum;DnsSent=($dns | Measure-Object Sent -Sum).Sum;DnsFailed=($dns | Measure-Object Lost -Sum).Sum;TcpAttempts=($tcp | Measure-Object Attempts -Sum).Sum;TcpFailed=($tcp | Measure-Object Failed -Sum).Sum;TcpDnsFailed=($tcp | Measure-Object DnsFailed -Sum).Sum;TcpAnswerBlocked=($tcp | Measure-Object AnswerBlocked -Sum).Sum;HttpsSent=($https | Measure-Object Sent -Sum).Sum;HttpsFailed=($https | Measure-Object Failed -Sum).Sum;AvailabilityJSON=($FamilyAvailability | ConvertTo-Json -Compress);StorageBytes=$Storage.Used;StorageDropped=$Storage.Dropped;RingRecords=$Ring.Count;IncidentDropped=$(if($Recorder){$Recorder.Dropped}else{0})}
    $record | Add-Member NoteProperty GatewayStatus $PingStats[$RouteInfo.Gateway].LastStatus
    $record | Add-Member NoteProperty GatewayLastMs $PingStats[$RouteInfo.Gateway].Last
    $record | Add-Member NoteProperty NicCountersJSON ($script:NicCurrent | ConvertTo-Json -Compress)
    $record | Add-Member NoteProperty TcpCountersJSON ($script:TcpStatsCurrent | ConvertTo-Json -Compress)
    Write-CsvRecord 'Health.csv' $record
}

function Invoke-StorageMaintenance {
    param([long]$NeedBytes=0)
    # Remove only named recorder artifacts in this exclusively owned namespace.
    $closed=New-Object 'System.Collections.Generic.List[object]';$logs=New-Object 'System.Collections.Generic.List[object]';$now=[datetime]::UtcNow
    foreach($run in Get-ChildItem -LiteralPath $SensorRoot -Directory -Filter 'Run_*'){
        $incidentDir=Join-Path $run.FullName 'Incidents'
        foreach($dir in Get-ChildItem -LiteralPath $incidentDir -Directory -ErrorAction SilentlyContinue){
            $marker=Join-Path $dir.FullName 'Closed.json'
            if(-not [IO.File]::Exists($marker) -or [IO.File]::Exists((Join-Path $dir.FullName 'Active.json')) -or ($Storage.Compression -and $Storage.Compression.Source -eq $dir.FullName)){continue}
            $m=[IO.File]::ReadAllText($marker) | ConvertFrom-Json
            if($m.SensorName -ne $Cfg.SENSOR_NAME){continue}
            $closed.Add([pscustomobject]@{Path=$dir.FullName;Time=(Convert-MonitorUtc $m.ClosedUTC);Zip=$false})
        }
        foreach($zip in Get-ChildItem -LiteralPath $incidentDir -Filter '*.zip' -File -ErrorAction SilentlyContinue){$closed.Add([pscustomobject]@{Path=$zip.FullName;Time=$zip.LastWriteTimeUtc;Zip=$true})}
        foreach($capture in Get-ChildItem -LiteralPath (Join-Path $run.FullName 'PacketCaptures') -Filter '*.etl' -File -ErrorAction SilentlyContinue){
            if($Storage.Reservations.ContainsKey($capture.FullName)){continue}
            if($capture.LastWriteTimeUtc -lt $now.AddDays(-$Cfg.PacketCaptureRetentionDays)){Remove-ManagedItem $capture.FullName;foreach($suffix in @('.status.txt','.capture.json')){if([IO.File]::Exists($capture.FullName+$suffix)){Remove-ManagedItem ($capture.FullName+$suffix)}};$Storage.Pruned++}else{$logs.Add([pscustomobject]@{Path=$capture.FullName;Time=$capture.LastWriteTimeUtc;Capture=$true})}
        }
        foreach($file in Get-ChildItem -LiteralPath (Join-Path $run.FullName 'Logs') -File -Recurse -ErrorAction SilentlyContinue){
            if($script:LogPaths.Values -contains $file.FullName){continue}
            $days=if($file.Name -like 'Health*' -or $file.Name -like 'Scheduler*'){$Cfg.HealthyRetentionDays}else{$Cfg.EventRetentionDays}
            if($file.LastWriteTimeUtc -lt $now.AddDays(-$days)){Remove-ManagedItem $file.FullName;$Storage.Pruned++}else{$logs.Add([pscustomobject]@{Path=$file.FullName;Time=$file.LastWriteTimeUtc;Capture=$false})}
        }
    }
    foreach($item in @($closed | Sort-Object Time)){
        if($item.Time -lt $now.AddDays(-$Cfg.IncidentRetentionDays)){Remove-ManagedItem $item.Path;[void]$closed.Remove($item);$Storage.Pruned++}
    }
    Update-StorageUsage
    # Quota pressure: oldest CLOSED incident first, then closed captures/log segments.
    foreach($item in @($closed | Sort-Object Time)){
        if($Storage.Used+$NeedBytes -le $Storage.Quota){break};Remove-ManagedItem $item.Path;[void]$closed.Remove($item);$Storage.Pruned++;Update-StorageUsage
    }
    foreach($item in @($logs | Sort-Object Time)){
        if($Storage.Used+$NeedBytes -le $Storage.Quota){break};Remove-ManagedItem $item.Path
        if($item.Capture){foreach($suffix in @('.status.txt','.capture.json')){if([IO.File]::Exists($item.Path+$suffix)){Remove-ManagedItem ($item.Path+$suffix)}}};$Storage.Pruned++;Update-StorageUsage
    }
    foreach($run in Get-ChildItem -LiteralPath $SensorRoot -Directory -Filter 'Run_*'){
        if($run.FullName -eq $RunDir -or -not [IO.File]::Exists((Join-Path $run.FullName 'Run_Closed.json'))){continue}
        $m=[IO.File]::ReadAllText((Join-Path $run.FullName 'Run_Closed.json')) | ConvertFrom-Json
        $evidence=@(Get-ChildItem -LiteralPath (Join-Path $run.FullName 'Incidents') -Force -ErrorAction SilentlyContinue)+@(Get-ChildItem -LiteralPath (Join-Path $run.FullName 'PacketCaptures') -Force -ErrorAction SilentlyContinue)
        if($m.SensorName -eq $Cfg.SENSOR_NAME -and (Convert-MonitorUtc $m.ClosedUTC) -lt $now.AddDays(-$Cfg.RunRetentionDays) -and -not $evidence.Count){Remove-ManagedItem $run.FullName;$Storage.Pruned++}
    }
    Update-StorageUsage
    $script:CompressionCandidates=@($closed | Where-Object{-not $_.Zip -and $_.Time -lt $now.AddHours(-$Cfg.CompressAfterHours)} | Sort-Object Time)
}

function Start-IncidentCompression {
    if(-not $Cfg.CompressClosedIncidents -or $Storage.Compression -or -not $CompressionCandidates.Count){return}
    $candidate=$CompressionCandidates[0];$source=$candidate.Path;$dest=$source+'.zip';$partial=$dest+'.partial'
    if([IO.File]::Exists($dest) -or [IO.File]::Exists($partial)){return}
    $files=@(Get-ChildItem -LiteralPath $source -Recurse -File);$size=[long]($files | Measure-Object Length -Sum).Sum
    $budget=$size+[long][math]::Ceiling($size/1000)+$files.Count*4096+1MB
    # Closed source is immutable. Reserve source size plus conservative deflate
    # and per-entry overhead; source+archive must coexist within the quota.
    if(-not (Reserve-Storage $partial $budget)){return}
    $ps=[powershell]::Create()
    $worker=@'
param($Source,$Partial,$Budget)
$ErrorActionPreference='Stop';Add-Type -AssemblyName System.IO.Compression
$files=@(Get-ChildItem -LiteralPath $Source -Recurse -File);$stream=[IO.File]::Open($Partial,[IO.FileMode]::CreateNew);$archive=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true)
try{foreach($file in $files){$entry=$archive.CreateEntry($file.FullName.Substring($Source.Length+1).Replace('\','/'),[IO.Compression.CompressionLevel]::Optimal);$input=[IO.File]::OpenRead($file.FullName);$output=$entry.Open();try{$input.CopyTo($output)}finally{$input.Dispose();$output.Dispose()};if($stream.Length -gt $Budget){throw 'Compression budget exceeded.'}}}finally{$archive.Dispose();$stream.Dispose()}
$stream=[IO.File]::OpenRead($Partial);$archive=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read)
try{if($archive.Entries.Count -ne $files.Count -or [long]($archive.Entries | Measure-Object Length -Sum).Sum -ne [long]($files | Measure-Object Length -Sum).Sum){throw 'Archive verification failed.'}}finally{$archive.Dispose()}
'@
    [void]$ps.AddScript($worker).AddArgument($source).AddArgument($partial).AddArgument($budget)
    $Storage.Compression=[pscustomobject]@{PowerShell=$ps;Handle=$ps.BeginInvoke();Source=$source;Partial=$partial;Destination=$dest;ClosedUTC=$candidate.Time}
}

function Step-Storage {
    if($Recorder -and $null -ne $Recorder.CloseMs -and $Clock.ElapsedMilliseconds -ge $Recorder.CloseMs -and -not ($EvidenceWorker -and $EvidenceWorker.IncidentPath -eq $Recorder.Path)){Close-IncidentRecorder}
    $job=$Storage.Compression
    if($job -and $job.Handle.IsCompleted){
        try{[void]$job.PowerShell.EndInvoke($job.Handle);if($job.PowerShell.Streams.Error.Count){throw ($job.PowerShell.Streams.Error | Out-String)};[IO.File]::Move($job.Partial,$job.Destination);[IO.File]::SetLastWriteTimeUtc($job.Destination,$job.ClosedUTC);Remove-ManagedItem $job.Source;Write-EventLog ('Compressed closed incident: '+$job.Destination) 'STORAGE_COMPRESSED'}catch{$script:LastCompressionError=$_.Exception.Message;if([IO.File]::Exists($job.Partial)){Remove-ManagedItem $job.Partial};Write-EventLog $_.Exception.Message 'STORAGE_WARNING'}finally{$job.PowerShell.Dispose();$Storage.Compression=$null;Release-StorageReservation $job.Partial}
    }
    if($Clock.ElapsedMilliseconds -ge $Storage.NextMaintenanceMs){
        $day=[datetime]::UtcNow.ToString('yyyyMMdd')
        foreach($name in @($script:LogPaths.Keys)){if([IO.Path]::GetFileName([IO.Path]::GetDirectoryName($script:LogPaths[$name])) -ne $day){if($Writers[$name]){$Writers[$name].Dispose();$Writers.Remove($name)};$script:LogPaths.Remove($name);$CsvHeaders.Remove($name)}}
        Invoke-StorageMaintenance -NeedBytes $Storage.Reserve;$Storage.NextMaintenanceMs=$Clock.ElapsedMilliseconds+$Cfg.StorageMaintenanceSec*1000;Start-IncidentCompression
    }
}

function Stop-Storage {
    if(-not $Storage){return}
    if($Storage.Compression){$job=$Storage.Compression;$job.PowerShell.Stop();$job.PowerShell.Dispose();if([IO.File]::Exists($job.Partial)){Remove-ManagedItem $job.Partial};$Storage.Compression=$null;Release-StorageReservation $job.Partial}
    Close-IncidentRecorder $(if($FatalErrorMessage){'FATAL_SHUTDOWN'}else{'GRACEFUL_SHUTDOWN'})
    if($RunDir){[void](Write-ManagedText (Join-Path $RunDir 'Run_Closed.json') (@{SensorName=$Cfg.SENSOR_NAME;SensorRole=$Cfg.SENSOR_ROLE;RunId=$RunId;ClosedUTC=[datetime]::UtcNow.ToString('o');Fatal=[bool]$FatalErrorMessage} | ConvertTo-Json) -Critical -Final)}
    Close-RunLogWriters
}
