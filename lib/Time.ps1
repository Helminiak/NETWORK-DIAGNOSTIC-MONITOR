# PowerShell 5.1 returns JSON date strings; newer versions may return DateTime.
# Converting a DateTime to a culture-dependent string before Parse loses its Kind.
function Convert-MonitorUtc {
    param($Value)
    if($Value -is [datetime]){return $Value.ToUniversalTime()}
    if($Value -is [datetimeoffset]){return $Value.UtcDateTime}
    return [datetimeoffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}
