function Set-ConsolePresentation {
    try {
        # Classic console only; no Forms assembly.

        $code = @"
using System;
using System.Runtime.InteropServices;

public static class ConsoleTune {
    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int nIndex);
    [StructLayout(LayoutKind.Sequential)]
    public struct COORD { public short X; public short Y; }

    [StructLayout(LayoutKind.Sequential)]
    public struct SMALL_RECT { public short Left; public short Top; public short Right; public short Bottom; }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CONSOLE_FONT_INFOEX {
        public uint cbSize;
        public uint nFont;
        public COORD dwFontSize;
        public int FontFamily;
        public int FontWeight;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)]
        public string FaceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONSOLE_SCREEN_BUFFER_INFOEX {
        public uint cbSize;
        public COORD dwSize;
        public COORD dwCursorPosition;
        public ushort wAttributes;
        public SMALL_RECT srWindow;
        public COORD dwMaximumWindowSize;
        public ushort wPopupAttributes;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bFullscreenSupported;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=16)]
        public uint[] ColorTable;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool SetCurrentConsoleFontEx(
        IntPtr hConsoleOutput,
        bool bMaximumWindow,
        ref CONSOLE_FONT_INFOEX lpConsoleCurrentFontEx
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetConsoleScreenBufferInfoEx(
        IntPtr hConsoleOutput,
        ref CONSOLE_SCREEN_BUFFER_INFOEX csbe
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetConsoleScreenBufferInfoEx(
        IntPtr hConsoleOutput,
        ref CONSOLE_SCREEN_BUFFER_INFOEX csbe
    );

    public static uint RGB(byte r, byte g, byte b) {
        return (uint)(r | (g << 8) | (b << 16));
    }
}
"@
        Add-Type $code -ErrorAction SilentlyContinue

        $screenH = [ConsoleTune]::GetSystemMetrics(1)
        $fontH = if($screenH -le 1080){14}elseif($screenH -le 1440){15}elseif($screenH -le 1800){16}else{18}

        $hOut = [ConsoleTune]::GetStdHandle(-11)

        # Font sizing based on display height.
        $fi = New-Object ConsoleTune+CONSOLE_FONT_INFOEX
        $fi.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($fi)
        $fi.nFont = 0
        $fi.dwFontSize = New-Object ConsoleTune+COORD
        $fi.dwFontSize.X = 0
        $fi.dwFontSize.Y = [int16]$fontH
        $fi.FontFamily = 54
        $fi.FontWeight = 400
        $fi.FaceName = 'Consolas'
        [void][ConsoleTune]::SetCurrentConsoleFontEx($hOut,$false,[ref]$fi)

        # Exact RGB console palette:
        # index 0 (Black) -> 20,20,20 background
        # index 7 (Gray)  -> 200,200,200 requested title/header text
        $cs = New-Object ConsoleTune+CONSOLE_SCREEN_BUFFER_INFOEX
        $cs.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($cs)
        $cs.ColorTable = New-Object uint32[] 16
        if([ConsoleTune]::GetConsoleScreenBufferInfoEx($hOut,[ref]$cs)){
            $cs.ColorTable[0] = [ConsoleTune]::RGB(20,20,20)
            $cs.ColorTable[7] = [ConsoleTune]::RGB(200,200,200)
            [void][ConsoleTune]::SetConsoleScreenBufferInfoEx($hOut,[ref]$cs)
        }

        try {
            $Host.UI.RawUI.BackgroundColor = 'Black'
            $Host.UI.RawUI.ForegroundColor = 'Gray'
            Clear-Host
        } catch {}
    } catch {}
}

function Add-HistorySample {
    param($History, [bool]$Success, [Nullable[double]]$Ms, [string]$Stage='', [datetime]$SampleTime=(Get-Date))
    $now = $SampleTime
    $mono=[long]([Diagnostics.Stopwatch]::GetTimestamp()*1000.0/[Diagnostics.Stopwatch]::Frequency)
    [void]$History.Add([pscustomobject]@{ Time=$now; MonoMs=$mono; Success=$Success; Ms=$Ms; Stage=$Stage })
    $cutoff = $mono-60000
    while ($History.Count -gt 0 -and $History[0].MonoMs -lt $cutoff) { $History.RemoveAt(0) }
}

function Get-RollingStats {
    param($History)
    $cutoff = [long]([Diagnostics.Stopwatch]::GetTimestamp()*1000.0/[Diagnostics.Stopwatch]::Frequency)-60000
    while($History.Count -gt 0 -and $History[0].MonoMs -lt $cutoff){$History.RemoveAt(0)}
    while($History.Count -gt 1024){$History.RemoveAt(0)}
    $count = $History.Count
    if ($count -eq 0) {
        return [pscustomobject]@{ Count=0; LossPct=0.0; Avg=$null; P95=$null; Jitter=$null }
    }

    $ok = @($History | Where-Object { $_.Success -and $null -ne $_.Ms })
    $lost = $count - $ok.Count
    $lossPct = [math]::Round(($lost / [double]$count) * 100,2)

    if ($ok.Count -eq 0) {
        return [pscustomobject]@{ Count=$count; LossPct=$lossPct; Avg=$null; P95=$null; Jitter=$null }
    }

    $vals = @($ok | ForEach-Object { [double]$_.Ms })
    $avg = [math]::Round((($vals | Measure-Object -Average).Average),1)
    $sorted = @($vals | Sort-Object)
    $idx = [math]::Ceiling($sorted.Count * 0.95) - 1
    if ($idx -lt 0) { $idx = 0 }
    $p95 = [math]::Round($sorted[$idx],1)

    $jitter = 0.0
    if ($vals.Count -gt 1) {
        $diffs = New-Object System.Collections.ArrayList
        for ($i=1; $i -lt $vals.Count; $i++) { [void]$diffs.Add([math]::Abs($vals[$i]-$vals[$i-1])) }
        $jitter = [math]::Round((($diffs | Measure-Object -Average).Average),1)
    }

    [pscustomobject]@{ Count=$count; LossPct=$lossPct; Avg=$avg; P95=$p95; Jitter=$jitter }
}

function Format-Num {
    param($Value, [int]$Decimals=0)
    if ($null -eq $Value) { return '-' }
    return ([math]::Round([double]$Value,$Decimals)).ToString()
}

function Get-NetworkWatchItems {
    $items = New-Object System.Collections.ArrayList

    # Public ICMP: intentionally higher thresholds than incident rules because
    # public DNS endpoints can rate-limit echo. These are advisory only.
    foreach($t in @($Targets | Where-Object { $_.Role -eq 'Public' })){
        $s = $PingStats[$t.IP]
        $r = Get-RollingStats $s.History
        if($r.Count -ge 8){
            if($s.LastStatus -in @('TimedOut','TIMEOUT','ERROR','DestinationHostUnreachable','DestinationNetworkUnreachable')){
                [void]$items.Add([pscustomobject]@{
                    Key=('PING:'+$t.Name); Severity='WARN';
                    Text=('{0} ICMP timeout; rolling loss {1:N1}% (ICMP-only, may be endpoint rate limiting).' -f $t.Name,$r.LossPct)
                })
            }
            elseif($r.LossPct -ge 10){
                [void]$items.Add([pscustomobject]@{
                    Key=('PING:'+$t.Name); Severity='WATCH';
                    Text=('{0} ICMP rolling loss {1:N1}%, P95 {2} ms (provider-specific ICMP; watch, not an outage by itself).' -f $t.Name,$r.LossPct,(Format-Num $r.P95 0))
                })
            }
            elseif(($null -ne $r.P95 -and $r.P95 -ge 100) -or ($null -ne $r.Avg -and $r.Avg -ge 75)){
                [void]$items.Add([pscustomobject]@{
                    Key=('PING:'+$t.Name); Severity='WATCH';
                    Text=('{0} ICMP latency elevated: Avg {1} ms, P95 {2} ms.' -f $t.Name,(Format-Num $r.Avg 0),(Format-Num $r.P95 0))
                })
            }
        }
    }

    # DNS: capture tail-latency problems even when queries still succeed.
    foreach($d in $AllDnsResolvers){
        $s = $DnsStats[$d.Name]
        $r = Get-RollingStats $s.History
        if($s.LastStatus -eq 'ANSWER_ANOMALY'){[void]$items.Add([pscustomobject]@{Key=('DNS:'+$d.Name);Severity='BAD';Text=($d.Name+' public-name DNS returned nonpublic addresses: '+($s.LastAddresses -join ',')+'. Wire reply is not trustworthy resolution.')})}
        elseif($s.LastStatus -eq 'FAIL'){
            [void]$items.Add([pscustomobject]@{
                Key=('DNS:'+$d.Name); Severity='BAD';
                Text=('{0} DNS query failed; server {1}.' -f $d.Name,$d.IP)
            })
        }
        elseif($r.Count -ge 3 -and (($null -ne $r.P95 -and $r.P95 -ge 250) -or ($null -ne $s.Last -and [double]$s.Last -ge 500))){
            [void]$items.Add([pscustomobject]@{
                Key=('DNS:'+$d.Name); Severity='WATCH';
                Text=('{0} DNS tail latency elevated: Last {1} ms, Avg60 {2} ms, P95 {3} ms.' -f $d.Name,(Format-Num $s.Last 0),(Format-Num $r.Avg 0),(Format-Num $r.P95 0))
            })
        }
    }

    # HTTPS: successful pages can still "feel stuck" because of TCP/TLS/TTFB latency.
    foreach($h in $HttpsSites){
        $s = $HttpsStats[$h.Name]
        if($s.LastStatus -eq 'FAIL'){
            [void]$items.Add([pscustomobject]@{
                Key=('HTTPS:'+$h.Name); Severity='BAD';
                Text=('{0} HTTPS failed at {1}.' -f $h.Name,$s.LastStage)
            })
        }
        elseif(($null -ne $s.LastTotal -and [double]$s.LastTotal -ge 1000) -or
               ($null -ne $s.LastTCP -and [double]$s.LastTCP -ge 500) -or
               ($null -ne $s.LastTLS -and [double]$s.LastTLS -ge 500) -or
               ($null -ne $s.LastTTFB -and [double]$s.LastTTFB -ge 750)){
            [void]$items.Add([pscustomobject]@{
                Key=('HTTPS:'+$h.Name); Severity='WATCH';
                Text=('{0} HTTPS slow: DNS {1} / TCP {2} / TLS {3} / TTFB {4} / Total {5} ms.' -f $h.Name,(Format-Num $s.LastDNS 0),(Format-Num $s.LastTCP 0),(Format-Num $s.LastTLS 0),(Format-Num $s.LastTTFB 0),(Format-Num $s.LastTotal 0))
            })
        }
    }

    # Dedicated TCP/443 probe.
    foreach($t in $TcpConnectTargets){
        $s = $TcpConnectStats[$t.Name]
        $r = Get-RollingStats $s.History
        if($s.LastStatus -eq 'FAIL'){
            $kind = if($s.LastStage -in @('DNS_FAIL','DNS_TIMEOUT')){'name resolution failed before TCP'}else{'TCP/443 connection failed'}
            [void]$items.Add([pscustomobject]@{
                Key=('TCP443:'+$t.Name); Severity='BAD';
                Text=('{0}: {1} at {2}.' -f $t.Name,$kind,$s.LastStage)
            })
        }
        elseif(($null -ne $s.LastConnect -and [double]$s.LastConnect -ge 500) -or ($r.Count -ge 3 -and $r.LossPct -gt 0)){
            [void]$items.Add([pscustomobject]@{
                Key=('TCP443:'+$t.Name); Severity='WATCH';
                Text=('{0} TCP/443 watch: connect {1} ms, Fail60 {2:N1}%.' -f $t.Name,(Format-Num $s.LastConnect 0),$r.LossPct)
            })
        }
    }

    # Local stack / NIC deltas.
    if($NicDelta -and ($NicDelta.RxErrors -gt 0 -or $NicDelta.TxErrors -gt 0 -or $NicDelta.RxDrops -gt 0 -or $NicDelta.TxDrops -gt 0)){
        [void]$items.Add([pscustomobject]@{
            Key='NIC:DELTA'; Severity='WARN';
            Text=('NIC counters changed: dRXerr={0}, dTXerr={1}, dRXdrop={2}, dTXdrop={3}.' -f $NicDelta.RxErrors,$NicDelta.TxErrors,$NicDelta.RxDrops,$NicDelta.TxDrops)
        })
    }

    if($TcpStatsDelta -and ($TcpStatsDelta.Failed -gt 0 -or $TcpStatsDelta.Errors -gt 0 -or $TcpStatsDelta.Retrans -ge 25)){
        [void]$items.Add([pscustomobject]@{
            Key='TCPSTACK:DELTA'; Severity='WATCH';
            Text=('Windows TCP counters: dRetrans={0}, dFailed={1}, dResets={2}, dErrors={3}.' -f $TcpStatsDelta.Retrans,$TcpStatsDelta.Failed,$TcpStatsDelta.Resets,$TcpStatsDelta.Errors)
        })
    }

    if($TopologyMode -eq 'ROUTER_BEHIND_BGW' -and $BgwTarget){
        $bs=$PingStats[$BgwTarget.IP];$br=Get-RollingStats $bs.History
        if($bs.LastStatus -in @('TimedOut','TIMEOUT','ERROR','DestinationHostUnreachable','DestinationNetworkUnreachable') -or ($br.Count -ge 5 -and $br.LossPct -ge 20)){
            [void]$items.Add([pscustomobject]@{Key='BGW:MGMT';Severity='WATCH';Text=('BGW management path {0} is degraded; correlate with public/TCP/DNS failures before blaming the WAN.' -f $BgwManagementIP)})
        }
    }

    # Keep a recent route change visible for 30 minutes.
    if($script:RouteChangedAt -and ((Get-Date)-$script:RouteChangedAt).TotalMinutes -le 30){
        [void]$items.Add([pscustomobject]@{
            Key='ROUTE:RECENT'; Severity='INFO';
            Text=('Traceroute replies changed at {0}; routing change is unproven. Retained for 30 minutes.' -f $script:RouteChangedAt.ToString('HH:mm:ss'))
        })
    }

    # Sort BAD -> WARN -> WATCH -> INFO and return a manageable live list.
    $rank = @{ BAD=0; WARN=1; WATCH=2; INFO=3 }
    return @($items | Sort-Object @{Expression={ $rank[$_.Severity] }},Text)
}

function Update-WatchHistory {
    param($Items)

    $new = @{}
    foreach($item in @($Items)){
        $new[$item.Key] = $item
        $started=-not $script:WatchActive.ContainsKey($item.Key)
        $logged=$started -and (-not $script:WatchLogAt.ContainsKey($item.Key) -or $Clock.ElapsedMilliseconds-$script:WatchLogAt[$item.Key] -ge $Cfg.AdvisoryLogCooldownSec*1000)
        if($started){Add-AdvisoryTransition $item $true $logged}
        if($logged){
            $script:WatchLogAt[$item.Key]=$Clock.ElapsedMilliseconds;$script:WatchLoggedActive[$item.Key]=$true
            Write-HistoryLog -Type ('WATCH_START') -Message ('[{0}] {1}' -f $item.Severity,$item.Text)
        }
    }

    foreach($key in @($script:WatchActive.Keys)){
        if(-not $new.ContainsKey($key)){
            $old = $script:WatchActive[$key]
            Add-AdvisoryTransition $old $false
            if($script:WatchLoggedActive.ContainsKey($key)){Write-HistoryLog -Type 'WATCH_CLEAR' -Message $old.Text;[void]$script:WatchLoggedActive.Remove($key)}
        }
    }

    $script:WatchActive = $new
}

function Render-Dashboard {
    param($Assessment, [datetime]$StartTime, [string]$LastDnsName, $WatchItems, $ForensicsItems, [switch]$FrameOnly)

    if(-not $script:DashboardInitialized -and -not $FrameOnly){
        Clear-Host
        $script:DashboardInitialized = $true
        $script:DashboardFrame = @()
    }

    $runtime = (Get-Date) - $StartTime
    $I = '   '

    # Use the current console width so a rewritten row does not wrap.
    try {
        $DashboardWidth = [Math]::Max(40, ([int]$Host.UI.RawUI.WindowSize.Width - 1))
    } catch {
        $DashboardWidth = 124
    }

    # Build the next screen in memory first. At the end of this function only
    # rows that actually changed are written to the console.
    $Frame = New-Object System.Collections.ArrayList

    function Write-Host {
        param(
            [Parameter(Position=0)][AllowNull()][object]$Object = '',
            [System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::Gray
        )
        $line = if($null -eq $Object){''}else{[string]$Object}
        [void]$Frame.Add([pscustomobject]@{
            Text  = $line
            Color = $ForegroundColor.ToString()
        })
    }

    function Write-PaddedLine {
        param([string]$Text,[string]$Color='Gray')
        $line = $I + [string]$Text
        Write-Host $line -ForegroundColor ([System.ConsoleColor][Enum]::Parse([System.ConsoleColor],$Color))
    }

    function Write-StatusRow {
        param([string]$Text,[string]$Status)
        $s = [string]$Status
        if($s -match 'STARTING|UNAVAILABLE|N/A') {
            Write-Host ($I + $Text) -ForegroundColor DarkGray
        } elseif($s -match 'FAIL|ANSWER_ANOMALY|DNS_ANSWER_NONPUBLIC|ERROR|TIMEOUT|TimedOut|Unreachable|CRITICAL'){
            Write-Host ($I + $Text) -ForegroundColor Red
        } elseif($s -match 'HIGH|ELEVATED|SLOW|WARNING|WATCH'){
            Write-Host ($I + $Text) -ForegroundColor DarkYellow
        } else {
            Write-Host ($I + $Text) -ForegroundColor Green
        }
    }

    Write-Host ($I + '========================================================================================================================') -ForegroundColor Cyan
    Write-Host ($I + '                                       NETWORK DIAGNOSTIC MONITOR V2.12-RC3.1.1') -ForegroundColor Gray
    Write-Host ($I + '========================================================================================================================') -ForegroundColor Cyan
    Write-Host ($I + ('Started: {0}    Runtime: {1:dd\.hh\:mm\:ss}    Current: {2}' -f $StartTime,$runtime,(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))) -ForegroundColor Green
    Write-Host ($I + ('Adapter: {0}    Link: {1}    Default Gateway: {2}    System DNS: {3}' -f $RouteInfo.AdapterName,$RouteInfo.LinkSpeed,$RouteInfo.Gateway,$RouteInfo.SystemDns)) -ForegroundColor Green
    Write-Host ($I + ('Run folder: {0}' -f $RunDir)) -ForegroundColor Green
    Write-Host ''

    if($script:LastErrorTime){
        $lc = if($script:LastErrorState -eq 'ACTIVE'){'Red'}elseif($script:LastErrorState -eq 'RECOVERED'){'DarkYellow'}else{'Green'}
        Write-PaddedLine -Text ('LAST CONFIRMED INCIDENT: {0} | {1} | {2}' -f $script:LastErrorTime.ToString('yyyy-MM-dd HH:mm:ss'),$script:LastErrorState,$script:LastErrorText) -Color $lc
    } else {
        $push=if($script:Alerts){$script:Alerts.Mode}else{'OFF'}
        Write-PaddedLine -Text ('LAST CONFIRMED INCIDENT: NONE since program start. | Pushover: '+$push) -Color 'Green'
    }
    Write-Host ''

    Write-Host ($I + 'PING / ROUTING (rolling 60 seconds)') -ForegroundColor Cyan
    Write-Host ($I + ('{0,-18} {1,-15} {2,6} {3,7} {4,6} {5,7} {6,9} {7,9} {8,7}  {9}' -f 'Server','IP','Last','Avg60','P95','Jitter','Loss60','TotLoss','MaxAll','Status')) -ForegroundColor Gray
    Write-Host ($I + ('{0,-18} {1,-15} {2,6} {3,7} {4,6} {5,7} {6,9} {7,9} {8,7}  {9}' -f '------','--','----','-----','---','------','------','-------','------','------')) -ForegroundColor DarkGray
    foreach ($t in $Targets) {
        $s = $PingStats[$t.IP]
        $r = Get-RollingStats $s.History
        $totalLoss = if($s.Sent -gt 0){[math]::Round(($s.Lost/[double]$s.Sent)*100,2)}else{0}
        $line = ('{0,-18} {1,-15} {2,6} {3,7} {4,6} {5,7} {6,9} {7,9} {8,7}  {9}' -f `
            $t.Name,$t.IP,(Format-Num $s.Last 0),(Format-Num $r.Avg 1),(Format-Num $r.P95 1),(Format-Num $r.Jitter 1),
            ('{0:N2}%' -f $r.LossPct),('{0:N2}%' -f $totalLoss),(Format-Num $(if($s.Received -gt 0){$s.Max}else{$null}) 0),$s.LastStatus)
        Write-StatusRow $line $s.LastStatus
    }

    Write-Host ''
    Write-Host ($I + ('DNS RESOLVERS - explicit resolver query: {0}' -f $LastDnsName)) -ForegroundColor Cyan
    Write-Host ($I + ('{0,-15} {1,-15} {2,-7} {3,7} {4,7} {5,7} {6,8}  {7}' -f 'Resolver','Server','Class','LastMs','Avg60','P95','Fail60','Status')) -ForegroundColor Gray
    Write-Host ($I + ('{0,-15} {1,-15} {2,-7} {3,7} {4,7} {5,7} {6,8}  {7}' -f '--------','------','-----','------','-----','---','------','------')) -ForegroundColor DarkGray
    foreach ($d in $AllDnsResolvers) {
        $s=$DnsStats[$d.Name]; $r=Get-RollingStats $s.History
        $line=('{0,-15} {1,-15} {2,-7} {3,7} {4,7} {5,7} {6,8}  {7}' -f `
            $d.Name,$d.IP,$d.Class,(Format-Num $s.Last 1),(Format-Num $r.Avg 1),(Format-Num $r.P95 1),('{0:N1}%' -f $r.LossPct),$s.LastStatus)
        Write-StatusRow $line $s.LastStatus
    }

    Write-Host ''
    Write-Host ($I + 'HTTPS TRANSACTION TIMING (milliseconds; most recent test)') -ForegroundColor Cyan
    if ($CurlExe) {
        Write-Host ($I + ('{0,-12} {1,7} {2,6} {3,6} {4,7} {5,8} {6,-16} {7,5}  {8}' -f 'Site','DNS','TCP','TLS','TTFB','Total','Stage','HTTP','Status')) -ForegroundColor Gray
        Write-Host ($I + ('{0,-12} {1,7} {2,6} {3,6} {4,7} {5,8} {6,-16} {7,5}  {8}' -f '----','---','---','---','----','-----','-----','----','------')) -ForegroundColor DarkGray
        foreach ($h in $HttpsSites) {
            $s=$HttpsStats[$h.Name]
            $line=('{0,-12} {1,7} {2,6} {3,6} {4,7} {5,8} {6,-16} {7,5}  {8}' -f `
                $h.Name,(Format-Num $s.LastDNS 1),(Format-Num $s.LastTCP 1),(Format-Num $s.LastTLS 1),(Format-Num $s.LastTTFB 1),(Format-Num $s.LastTotal 1),$s.LastStage,$s.LastCode,$s.LastStatus)
            Write-StatusRow $line $s.LastStatus
        }
    } else {
        Write-Host ($I + 'curl.exe not found; HTTPS timing is unavailable on this system.') -ForegroundColor Red
    }

    Write-Host ''
    Write-Host ($I + 'TCP / 443 CONNECT') -ForegroundColor Cyan
    Write-Host ($I + ('{0,-14} {1,9} {2,9} {3,-16}  {4}' -f 'Site','Connect','Fail60','Stage','Status')) -ForegroundColor Gray
    Write-Host ($I + ('{0,-14} {1,9} {2,9} {3,-16}  {4}' -f '----','-------','------','-----','------')) -ForegroundColor DarkGray
    foreach($t in $TcpConnectTargets){
        $s=$TcpConnectStats[$t.Name]
        $r=Get-RollingStats $s.History
        $line=('{0,-14} {1,9} {2,9} {3,-16}  {4}' -f $t.Name,(Format-Num $s.LastConnect 1),('{0:N1}%' -f $r.LossPct),$s.LastStage,$s.LastStatus)
        Write-StatusRow $line $s.LastStatus
    }

    Write-Host ''
    Write-Host ($I + 'DNS TRANSPORT (UDP / TCP53 / DoH endpoint timing)') -ForegroundColor Cyan
    Write-Host ($I + ('{0,-15} {1,-12} {2,-12} {3,-12}' -f 'Resolver','UDP','TCP53','DoH')) -ForegroundColor Gray
    Write-Host ($I + ('{0,-15} {1,-12} {2,-12} {3,-12}' -f '--------','---','-----','---')) -ForegroundColor DarkGray
    foreach($d in $DnsTransportResolvers){
        $s=$DnsTransportStats[$d.Name]
        $udp = ('{0}/{1}ms' -f $s.LastUDP,(Format-Num $s.LastUDPms 0))
        $tcp = ('{0}/{1}ms' -f $s.LastTCP53,(Format-Num $s.LastTCP53ms 0))
        $doh = if($s.LastDoH -eq 'N/A'){'N/A'}else{('{0}/{1}ms' -f $s.LastDoH,(Format-Num $s.LastDoHms 0))}
        $combined = "$($s.LastUDP) $($s.LastTCP53) $($s.LastDoH)"
        # An unconfigured DoH check does not invalidate UDP/TCP results. A real
        # failure takes precedence even while another transport is still pending.
        $rowStatus = if($combined -match 'FAIL|ANSWER_ANOMALY|DNS_ANSWER_NONPUBLIC|ERROR|TIMEOUT|TimedOut|Unreachable|CRITICAL'){'FAIL'}elseif($s.LastUDP -eq '-' -or $s.LastTCP53 -eq '-'){'STARTING'}else{$combined -replace 'N/A',''}
        $line=('{0,-15} {1,-12} {2,-12} {3,-12}' -f $d.Name,$udp,$tcp,$doh)
        Write-StatusRow $line $rowStatus
    }

    Write-Host ''
    Write-Host ($I + 'LOCAL STACK') -ForegroundColor Cyan
    if($TcpStatsCurrent){
        $d='Delta unavailable'
        if($TcpStatsDelta){$d=('dRetrans={0} dFailed={1} dResets={2} dErrors={3}' -f $TcpStatsDelta.Retrans,$TcpStatsDelta.Failed,$TcpStatsDelta.Resets,$TcpStatsDelta.Errors)}
        $stackStatus = if($TcpStatsDelta -and ($TcpStatsDelta.Failed -ge 3 -or $TcpStatsDelta.Errors -gt 0)){'FAIL'}elseif($TcpStatsDelta -and $TcpStatsDelta.Retrans -ge 25){'HIGH'}else{'OK'}
        Write-StatusRow ('TCP  Retrans={0} FailedConnect={1} Resets={2} Errors={3} | {4}' -f $TcpStatsCurrent.SegmentsRetransmitted,$TcpStatsCurrent.FailedConnectionAttempts,$TcpStatsCurrent.ResetConnections,$TcpStatsCurrent.ErrorsReceived,$d) $stackStatus
    } else {
        Write-Host ($I + 'TCP statistics not available yet.') -ForegroundColor DarkGray
    }

    if ($NicCurrent) {
        $deltaText='n/a'
        if ($NicDelta) { $deltaText=('dRXerr={0} dTXerr={1} dRXdrop={2} dTXdrop={3}' -f $NicDelta.RxErrors,$NicDelta.TxErrors,$NicDelta.RxDrops,$NicDelta.TxDrops) }
        $nicStatus = if($NicDelta -and ($NicDelta.RxErrors -gt 0 -or $NicDelta.TxErrors -gt 0 -or $NicDelta.RxDrops -gt 5 -or $NicDelta.TxDrops -gt 5)){'FAIL'}else{'OK'}
        Write-StatusRow ('NIC  {0} | {1} | RXerr={2} TXerr={3} RXdrop={4} TXdrop={5} | {6}' -f $NicCurrent.Name,$NicCurrent.LinkSpeed,$NicCurrent.RxErrors,$NicCurrent.TxErrors,$NicCurrent.RxDrops,$NicCurrent.TxDrops,$deltaText) $nicStatus
    } else {
        Write-Host ($I + 'NIC statistics not available yet.') -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host ($I + 'BACKGROUND FORENSICS') -ForegroundColor Cyan
    Write-Host ($I + ('{0,-18} {1,-9} {2}' -f 'Subsystem','State','Detail')) -ForegroundColor Gray
    Write-Host ($I + ('{0,-18} {1,-9} {2}' -f '---------','-----','------')) -ForegroundColor DarkGray
    foreach($f in @($ForensicsItems)){
        $line = ('{0,-18} {1,-9} {2}' -f $f.Name,$f.State,$f.Text)
        $fc = if($f.State -eq 'BAD'){'Red'}elseif($f.State -in @('WATCH','WAITING')){'DarkYellow'}elseif($f.State -eq 'OFF'){'Gray'}else{'Green'}
        Write-PaddedLine -Text $line -Color $fc
    }

    Write-Host ''
    Write-Host ($I + 'CURRENT NETWORK WATCHLIST') -ForegroundColor Cyan
    $watchRows = New-Object System.Collections.ArrayList
    if(@($WatchItems).Count -eq 0){
        [void]$watchRows.Add([pscustomobject]@{Text='NONE - Network is healthy and no secondary conditions currently exceed watch thresholds.';Color='Green'})
    } else {
        $show = @($WatchItems | Select-Object -First 4)
        foreach($w in $show){
            $prefix = ('[{0}]' -f $w.Severity)
            $color = if($w.Severity -eq 'BAD'){'Red'}elseif($w.Severity -in @('WARN','WATCH')){'DarkYellow'}else{'Gray'}
            [void]$watchRows.Add([pscustomobject]@{Text=($prefix + ' ' + $w.Text);Color=$color})
        }
        if(@($WatchItems).Count -gt 4){
            [void]$watchRows.Add([pscustomobject]@{Text=('... plus {0} additional watch item(s); full history is in Network_History.log.' -f (@($WatchItems).Count-4));Color='DarkGray'})
        }
    }
    while($watchRows.Count -lt 5){ [void]$watchRows.Add([pscustomobject]@{Text='';Color='Gray'}) }
    foreach($row in @($watchRows | Select-Object -First 5)){ Write-PaddedLine -Text $row.Text -Color $row.Color }

    Write-Host ''
    Write-Host ($I + 'RECENT NETWORK HISTORY') -ForegroundColor Cyan
    $recent = @(Get-RecentNetworkHistory -Count 5)
    $historyRows = New-Object System.Collections.ArrayList
    if($recent.Count -eq 0){
        [void]$historyRows.Add([pscustomobject]@{Text='No incidents or watch-state changes have been recorded yet.';Color='Green'})
    } else {
        foreach($line in $recent){
            $display = [string]$line
            if($display.Length -gt 116){ $display = $display.Substring(0,113) + '...' }
            $color = if($display -match 'INCIDENT|FAIL|WATCH_START.*BAD'){'Red'}elseif($display -match 'WATCH_START|ROUTE_CHANGE|WARNING'){'DarkYellow'}elseif($display -match 'RECOVERY|WATCH_CLEAR'){'Green'}else{'Gray'}
            [void]$historyRows.Add([pscustomobject]@{Text=$display;Color=$color})
        }
    }
    while($historyRows.Count -lt 5){ [void]$historyRows.Add([pscustomobject]@{Text='';Color='Gray'}) }
    foreach($row in @($historyRows | Select-Object -First 5)){ Write-PaddedLine -Text $row.Text -Color $row.Color }

    Write-Host ''
    if ($Assessment.Severity -eq 'CRITICAL') {
        Write-PaddedLine -Text ('ASSESSMENT: {0} - {1}' -f $Assessment.Code,$Assessment.Text) -Color 'Red'
    } elseif ($Assessment.Severity -eq 'WARNING') {
        Write-PaddedLine -Text ('ASSESSMENT: {0} - {1}' -f $Assessment.Code,$Assessment.Text) -Color 'DarkYellow'
    } else {
        Write-PaddedLine -Text ('ASSESSMENT: {0} - {1}' -f $Assessment.Code,$Assessment.Text) -Color 'Green'
    }

    Write-Host ($I + 'Event rules: independent protocols + new timestamped evidence; ICMP-only is WATCH.') -ForegroundColor Green
    Write-Host ($I + 'Traceroutes run silently in the background. Press Q or CTRL+C to stop. Health summaries + bounded incident logs.') -ForegroundColor DarkGray

    # Realtime line-diff renderer:
    # - no full-screen clear after startup
    # - only changed rows are touched
    # - each changed row is replaced across the full console width, which
    #   clears any older/longer text on that row without flashing the screen
    if($FrameOnly){return @($Frame)}
    # Resize invalidates row comparisons but never clears the screen.
    $oldFrame = if($script:DashboardLastWidth -ne $DashboardWidth){@()}else{@($script:DashboardFrame)}
    $script:DashboardLastWidth=$DashboardWidth
    try{if([Console]::BufferHeight -lt $Frame.Count+2){[Console]::BufferHeight=$Frame.Count+2}}catch{}
    $newFrame = @($Frame)
    $maxRows = [Math]::Max($oldFrame.Count,$newFrame.Count)

    for($row=0; $row -lt $maxRows; $row++){
        $newText = ''
        $newColor = 'Gray'
        if($row -lt $newFrame.Count){
            $newText = [string]$newFrame[$row].Text
            $newColor = [string]$newFrame[$row].Color
        }

        $oldText = $null
        $oldColor = $null
        if($row -lt $oldFrame.Count){
            $oldText = [string]$oldFrame[$row].Text
            $oldColor = [string]$oldFrame[$row].Color
        }

        if(($newText -ne $oldText) -or ($newColor -ne $oldColor)){
            try {
                [Console]::SetCursorPosition(0,$row)
                try {
                    [Console]::ForegroundColor = [System.ConsoleColor][Enum]::Parse([System.ConsoleColor],$newColor)
                } catch {
                    [Console]::ForegroundColor = [System.ConsoleColor]::Gray
                }

                # Full-width replacement = clear this line + write new content in
                # one operation. This avoids the blank-screen / redraw flash.
                $display = $newText
                if($display.Length -gt $DashboardWidth){
                    $display = $display.Substring(0,$DashboardWidth)
                }
                if($display.Length -lt $DashboardWidth){
                    $display = $display.PadRight($DashboardWidth)
                }
                [Console]::Write($display)
            } catch {
                # Fallback only if direct cursor addressing is unavailable.
                Microsoft.PowerShell.Utility\Write-Host $newText -ForegroundColor Gray
            }
        }
    }

    $script:DashboardFrame = $newFrame

    # Keep the hidden cursor parked below the dashboard without clearing anything.
    try {
        $parkRow = [Math]::Min([Math]::Max(0,$newFrame.Count),([Console]::BufferHeight-1))
        [Console]::SetCursorPosition(0,$parkRow)
    } catch {}
}
