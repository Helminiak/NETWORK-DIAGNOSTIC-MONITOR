# Portable policy helpers. A public address is NOT proof of authenticity or DNSSEC.
function Test-PublicProbeAddress {
    param([string]$Address)
    $ip=$null
    if(-not [Net.IPAddress]::TryParse($Address,[ref]$ip)){return $false}
    if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return $false}
    $b=$ip.GetAddressBytes()
    if($b[0] -in @(0,10,127) -or $b[0] -ge 224){return $false}
    if($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127){return $false}
    if($b[0] -eq 169 -and $b[1] -eq 254){return $false}
    if($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31){return $false}
    if($b[0] -eq 192 -and ($b[1] -eq 168 -or ($b[1] -eq 0 -and $b[2] -in @(0,2)) -or ($b[1] -eq 88 -and $b[2] -eq 99))){return $false}
    if($b[0] -eq 198 -and ($b[1] -in @(18,19) -or ($b[1] -eq 51 -and $b[2] -eq 100))){return $false}
    if($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113){return $false}
    return $true
}

function Get-DnsAnswerPolicy {
    param([string]$Name,$Addresses,$Config)
    if(-not $Config.ExpectPublicDnsAnswers -or $Name.TrimEnd('.') -in @($Config.AllowedPrivateDnsNames)) {return 'EXEMPT'}
    if(@($Addresses).Count -eq 0){return 'NO_ADDRESS'}
    foreach($ip in $Addresses){if(-not (Test-PublicProbeAddress ([string]$ip))){return 'PUBLIC_NAME_NONPUBLIC_ANSWER'}}
    return 'PUBLIC_ADDRESS_ONLY'
}

function Test-ObservationAnswerAnomaly {
    param($Row,$Config)
    if($Row.Protocol -in @('DNS_UDP','DNS_TCP') -and $Row.Status -eq 'OK' -and $Row.Data.QueryName){
        return (Get-DnsAnswerPolicy $Row.Data.QueryName $Row.Data.Addresses $Config) -eq 'PUBLIC_NAME_NONPUBLIC_ANSWER'
    }
    if($Row.Protocol -eq 'TCP443' -and $Row.Data.HostName -and $Row.Data.IP){
        $parsed=$null
        if(-not [Net.IPAddress]::TryParse($Row.Data.HostName,[ref]$parsed)){
            return (Get-DnsAnswerPolicy $Row.Data.HostName @($Row.Data.IP) $Config) -eq 'PUBLIC_NAME_NONPUBLIC_ANSWER'
        }
    }
    return $false
}

function Test-ObservationUsableSuccess {
    param($Row,$Config)
    return $Row.Status -eq 'OK' -and -not (Test-ObservationAnswerAnomaly $Row $Config)
}
