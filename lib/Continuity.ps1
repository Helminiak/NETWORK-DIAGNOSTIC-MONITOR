# Coordinator liveness is independent of network reachability.
# Logging an interruption never implies a gateway/ISP outage.
function New-ContinuityState {
    param([long]$StartMs=0,[datetime]$StartUtc=[datetime]::UtcNow)
    return [pscustomobject]@{
        LastTickMs=$StartMs;LastUtc=$StartUtc;GapCount=0L;BlindMs=0L;
        LongestGapMs=0L;LastGapUtc=$null;ClockCorrectionCount=0L
    }
}
function Update-ContinuityState {
    param($Continuity,[long]$NowMs,[datetime]$NowUtc,[long]$ThresholdMs)
    $elapsed=$NowMs-$Continuity.LastTickMs
    $wall=[long][math]::Round(($NowUtc-$Continuity.LastUtc).TotalMilliseconds)
    if($elapsed -lt 0){throw 'Monotonic stopwatch moved backward; cannot establish scheduler continuity.'}
    $Continuity.LastTickMs=$NowMs;$Continuity.LastUtc=$NowUtc
    # Time synchronization / manual changes do not count as sensor outages.
    if([math]::Abs($wall-$elapsed) -gt 5000){$Continuity.ClockCorrectionCount++}
    if($elapsed -le $ThresholdMs){return $null}
    $Continuity.GapCount++
    # Conservative classification: no main-loop ticks occurred for this period.
    $Continuity.BlindMs+=$elapsed
    $Continuity.LongestGapMs=[math]::Max($Continuity.LongestGapMs,$elapsed)
    $Continuity.LastGapUtc=$NowUtc.ToString('o')
    return [pscustomobject]@{Type='SENSOR_GAP';ElapsedMs=$elapsed;WallMs=$wall;
        ClockDeltaMs=($wall-$elapsed);TimestampUTC=$NowUtc.ToString('o')}
}
function Reset-InFlightBudgetAfterGap {
    param($Scheduler,[long]$NowMs)
    # Host sleep/suspension is not a worker deadlock. Allow a fresh worker budget.
    # Completed handles are processed normally on the next scheduler step.
    foreach($job in $Scheduler.Jobs.Values){
        if($job.Handle -and -not $job.Handle.IsCompleted){$job.StartedMs=$NowMs}
    }
}

function Reset-IncidentAfterGap {
    param($State)
    $State.Candidate=$null;$State.FirstStreams=@{};$State.LastStreams=@{}
    $State.RecoveryFirstMs=$null;$State.RecoveryStreams=@{}
    # Retain a confirmed incident until new, post-gap successes recover it.
}
