#Requires -Version 5.1
param([string]$RootDir='',[string]$Destination='',[string]$SensorName='')
$ErrorActionPreference='Stop';$archive=$null;$archiveStream=$null;$temporary=$null
try{
    $cfg=Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'Monitor_Config.psd1')
    if(-not $RootDir){$RootDir=$cfg.RootDir}
    if(-not $SensorName){$SensorName=if($cfg.SENSOR_NAME){$cfg.SENSOR_NAME}else{$env:COMPUTERNAME}}
    if($SensorName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'){throw 'Invalid sensor name.'}
    $RootDir=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RootDir)
    $sensorRoot=if([IO.File]::Exists((Join-Path $RootDir 'Storage_Owner.json'))){$RootDir}else{Join-Path $RootDir $SensorName}
    $latest=Get-ChildItem -LiteralPath $sensorRoot -Directory -Filter 'Run_*' | Sort-Object Name -Descending | Select-Object -First 1
    if(-not $latest){throw ('No V2.12-RC3 run found under '+$RootDir)}
    $runConfig=[IO.File]::ReadAllText((Join-Path $latest.FullName 'Configuration.json')) | ConvertFrom-Json
    if(-not $Destination){$packages=Join-Path $RootDir 'Packages';[void][IO.Directory]::CreateDirectory($packages);$Destination=Join-Path $packages ('Network_Diagnostic_V2_12_RC3_'+$latest.Name+'_'+[datetime]::Now.ToString('yyyyMMdd_HHmmss')+'.zip')}
    $Destination=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
    # Exports are explicit user copies, outside the recorder's managed quota.
    # Refuse a destination inside managed storage so the governor cannot delete it.
    if($Destination.StartsWith($sensorRoot.TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Choose an export destination outside the managed sensor directory.'}
    if([IO.File]::Exists($Destination)){throw 'Destination ZIP already exists; choose a new path.'}
    $temporary=$Destination+'.'+[guid]::NewGuid().ToString('N')+'.partial'
    Add-Type -AssemblyName System.IO.Compression
    $archiveStream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $archive=[IO.Compression.ZipArchive]::new($archiveStream,[IO.Compression.ZipArchiveMode]::Create,$false)
    $omitted=New-Object 'System.Collections.Generic.List[string]';$count=0
    foreach($file in Get-ChildItem -LiteralPath $latest.FullName -Recurse -File | Where-Object{$_.Extension -notin @('.tmp','.partial','.clixml')}){
        $inputStream=$null;$entryStream=$null
        try{
            if($file.Extension -eq '.etl' -and (-not [IO.File]::Exists($file.FullName+'.status.txt') -or [IO.File]::ReadAllText($file.FullName+'.status.txt') -notmatch 'StopExit=0\b')){$omitted.Add($file.FullName+': capture not confirmed stopped');continue}
            # Capture each file's byte length once. Growing CSVs end at the previous
            # complete newline; archive copies are immutable even while a run continues.
            $inputStream=[IO.FileStream]::new($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            $remaining=$inputStream.Length
            if($file.Extension -in @('.csv','.log','.jsonl') -and $remaining -gt 0){
                $position=$remaining-1
                while($position -gt 0){$inputStream.Position=$position;if($inputStream.ReadByte() -eq 10){break};$position--}
                $remaining=if($position -gt 0){$position+1}else{0};$inputStream.Position=0
            }
            $relative=$file.FullName.Substring($latest.FullName.Length+1).Replace('\','/')
            $entry=$archive.CreateEntry($relative,[IO.Compression.CompressionLevel]::Optimal);$entryStream=$entry.Open()
            $buffer=New-Object byte[] 65536
            while($remaining -gt 0){$read=$inputStream.Read($buffer,0,[int][math]::Min($buffer.Length,$remaining));if($read -eq 0){throw 'Source shortened during copy.'};$entryStream.Write($buffer,0,$read);$remaining-=$read}
            $count++
        }catch{
            if($file.Extension -in @('.etl','.pcapng') -or -not [IO.File]::Exists($file.FullName)){$omitted.Add($file.FullName+': '+$_.Exception.Message)}else{throw}
        }finally{if($entryStream){$entryStream.Dispose()};if($inputStream){$inputStream.Dispose()}}
    }
    $entry=$archive.CreateEntry('Package_Status.txt');$writer=[IO.StreamWriter]::new($entry.Open())
    try{$writer.WriteLine('Snapshot UTC: '+[datetime]::UtcNow.ToString('o'));$writer.WriteLine('Sensor: '+$runConfig.SensorName+' Role: '+$runConfig.SensorRole);$writer.WriteLine('Run: '+$latest.Name);$writer.WriteLine('Files: '+$count);$writer.WriteLine('Live-run snapshots are not transactionally simultaneous across files. Retention may prune closed files during export. Stop the monitor first for a final bundle. Exported copies are outside automatic retention/quota.');foreach($line in $omitted){$writer.WriteLine('Omitted: '+$line)}}finally{$writer.Dispose()}
    $archive.Dispose();$archive=$null;$archiveStream=$null
    [IO.File]::Move($temporary,$Destination);$temporary=$null
    Write-Host ('Created: '+$Destination) -ForegroundColor Green
    if($omitted.Count){Write-Host ('Active capture files omitted: '+$omitted.Count+'. Details in Package_Status.txt; package again after capture finishes.') -ForegroundColor Yellow}
}catch{Write-Host ('Packaging failed: '+$_.Exception.Message) -ForegroundColor Red;exit 1}
finally{if($archive){$archive.Dispose()};if($archiveStream){$archiveStream.Dispose()};if($temporary -and [IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
