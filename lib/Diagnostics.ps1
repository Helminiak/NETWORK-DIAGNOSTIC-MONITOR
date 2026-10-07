# Bounded cumulative diagnostics survive healthy periods without per-probe CSV.
function Add-FailureStageCount {
    param($Row)
    if($Row.Status -ne 'FAIL'){return}
    if(-not $script:FailureStages){$script:FailureStages=@{}}
    $stage=$Row.Stage
    if($Row.Protocol -eq 'TCP443' -and $Row.Data.DnsDetail){$stage+=':'+$Row.Data.DnsDetail}
    $key=$Row.Family+':'+$Row.Protocol+':'+$Row.Name+':'+$stage
    if(-not $script:FailureStages.ContainsKey($key)){
        if($script:FailureStages.Count -ge 128){$script:FailureStageOmitted++;return}
        $script:FailureStages[$key]=[pscustomobject]@{family=$Row.Family;protocol=$Row.Protocol;name=$Row.Name;stage=$stage;count=0L;lastErrorType=$null;lastSocketError=$null;lastNativeErrorCode=$null}
    }
    $bucket=$script:FailureStages[$key];$bucket.count++
    if($Row.Data.Error){$bucket.lastErrorType=$Row.Data.Error.type;$bucket.lastSocketError=$Row.Data.Error.socketError;$bucket.lastNativeErrorCode=$Row.Data.Error.nativeErrorCode}
}

function Get-FailureStageSummary {
    return @($script:FailureStages.Values | Sort-Object count -Descending)
}

function Add-DnsFallbackCount {
    param($Row)
    if($Row.Protocol -ne 'TCP443' -or $Row.Data.DnsFallbackReason -ne 'TRUNCATED'){return}
    if(-not $script:DnsFallbacks){$script:DnsFallbacks=@{}}
    if(-not $script:DnsFallbacks.ContainsKey($Row.Name)){
        if($script:DnsFallbacks.Count -ge 128){$script:DnsFallbackOmitted++;return}
        $script:DnsFallbacks[$Row.Name]=[pscustomobject]@{name=$Row.Name;attempts=0L;resolved=0L;failed=0L}
    }
    $counter=$script:DnsFallbacks[$Row.Name];$counter.attempts++
    if($Row.Data.TcpAttempted -or $Row.Stage -eq 'DNS_ANSWER_NONPUBLIC'){$counter.resolved++}else{$counter.failed++}
}

function Get-DnsFallbackSummary {return @($script:DnsFallbacks.Values | Sort-Object name)}

function Add-AdvisoryTransition {
    param($Item,[bool]$Started,[bool]$Logged=$false)
    if(-not $script:AdvisoryCounters){$script:AdvisoryCounters=@{}}
    if(-not $script:AdvisoryCounters.ContainsKey($Item.Key)){
        if($script:AdvisoryCounters.Count -ge 128){$script:AdvisoryKeysOmitted++;return}
        $script:AdvisoryCounters[$Item.Key]=[pscustomobject]@{key=$Item.Key;starts=0L;clears=0L;loggedStarts=0L;suppressedStarts=0L;severity=$Item.Severity}
    }
    $counter=$script:AdvisoryCounters[$Item.Key];$counter.severity=$Item.Severity
    if($Started){$counter.starts++;if($Logged){$counter.loggedStarts++}else{$counter.suppressedStarts++}}else{$counter.clears++}
}

function Get-AdvisorySummary {
    return @($script:AdvisoryCounters.Values | Sort-Object starts -Descending | ForEach-Object{
        [pscustomobject]@{key=$_.key;starts=$_.starts;clears=$_.clears;loggedStarts=$_.loggedStarts;suppressedStarts=$_.suppressedStarts;severity=$_.severity;active=$script:WatchActive.ContainsKey($_.key)}
    })
}

function Get-CurrentLinkSpeed {
    $maxAge=[long]([math]::Max(30,$script:Cfg.Schedules.NIC.IntervalSec*3)*1000)
    if($script:NicCurrent -and $script:NicCurrent.Status -eq 'OK' -and $null -ne $script:NicMonoMs -and $script:Clock.ElapsedMilliseconds-$script:NicMonoMs -le $maxAge){return $script:NicCurrent.LinkSpeed}
    return $null
}
