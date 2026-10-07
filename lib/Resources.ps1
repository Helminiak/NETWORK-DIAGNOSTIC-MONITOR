# Process diagnostics use monotonic deltas and never force garbage collection.
function Get-ProcessCpuDelta {
    param([double]$CpuMs,$Previous,[long]$NowMs)
    if(-not $Previous -or $NowMs -le $Previous.monoMs -or $CpuMs -lt $Previous.cpuTotalMs){return $null}
    # 100% means one logical CPU; a multithreaded process may exceed 100%.
    return [math]::Round(100.0*($CpuMs-$Previous.cpuTotalMs)/($NowMs-$Previous.monoMs),2)
}

function Update-ProcessResources {
    param([switch]$Reset)
    $now=[long]$script:Clock.ElapsedMilliseconds;$process=$null
    try{
        $process=[Diagnostics.Process]::GetCurrentProcess();$process.Refresh()
        $cpu=[double]$process.TotalProcessorTime.TotalMilliseconds
        $cpuAvailable=$cpu -gt 0
        $resident=if($process.WorkingSet64 -gt 0){[long]$process.WorkingSet64}else{$null}
        $peak=if($process.PeakWorkingSet64 -gt 0){[long]$process.PeakWorkingSet64}else{$null}
        $privateMemory=if($process.PrivateMemorySize64 -gt 0){[long]$process.PrivateMemorySize64}else{$null}
        $unavailable=@(if(-not $cpuAvailable){'CPU'};if($null -eq $resident){'WorkingSet'};if($null -eq $peak){'PeakWorkingSet'};if($null -eq $privateMemory){'PrivateBytes'})
        $previous=if($Reset -or -not $cpuAvailable){$null}else{$script:ResourcePrevious}
        $script:ProcessResources=[pscustomobject]@{
            status=if($unavailable.Count){'PARTIAL'}else{'OK'};scope='MONITOR_PROCESS';monoMs=$now;unavailableFields=$unavailable
            cpuPercentOneCore=(Get-ProcessCpuDelta $cpu $previous $now)
            workingSetBytes=$resident
            peakWorkingSetBytes=$peak
            privateBytes=$privateMemory
            managedHeapBytes=[long][GC]::GetTotalMemory($false)
        }
        $script:ResourcePrevious=if($cpuAvailable){[pscustomobject]@{monoMs=$now;cpuTotalMs=$cpu}}else{$null}
    }catch{
        $script:ResourcePrevious=$null
        $script:ProcessResources=[pscustomobject]@{status='UNAVAILABLE';scope='MONITOR_PROCESS';monoMs=$now;cpuPercentOneCore=$null;workingSetBytes=$null;peakWorkingSetBytes=$null;privateBytes=$null;managedHeapBytes=$null}
    }finally{if($process){$process.Dispose()}}
}

function Get-ProcessResourceSnapshot {
    param([string]$Lifecycle='RUNNING')
    $sample=$script:ProcessResources
    if(-not $sample -or $Lifecycle -eq 'HISTORICAL'){
        return [pscustomobject]@{status='UNMEASURED';scope='MONITOR_PROCESS';monoMs=$null;ageMs=$null;cpuPercentOneCore=$null;workingSetBytes=$null;peakWorkingSetBytes=$null;privateBytes=$null;managedHeapBytes=$null}
    }
    $age=[math]::Max(0,[long]$script:Clock.ElapsedMilliseconds-$sample.monoMs)
    $current=$sample.status -in @('OK','PARTIAL') -and $age -le 90000
    [pscustomobject]@{status=if($age -gt 90000){'STALE'}else{$sample.status};scope=$sample.scope;unavailableFields=$sample.unavailableFields;monoMs=$sample.monoMs;ageMs=$age;cpuPercentOneCore=if($current){$sample.cpuPercentOneCore}else{$null};workingSetBytes=if($current){$sample.workingSetBytes}else{$null};peakWorkingSetBytes=if($current){$sample.peakWorkingSetBytes}else{$null};privateBytes=if($current){$sample.privateBytes}else{$null};managedHeapBytes=if($current){$sample.managedHeapBytes}else{$null}}
}
