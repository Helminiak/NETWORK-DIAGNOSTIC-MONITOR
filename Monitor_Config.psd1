@{
# Set this explicitly on each machine. GENERIC makes no ASUS/BGW ownership claim.
SENSOR_NAME = ''                 # blank uses COMPUTERNAME; set a unique name for clones
SENSOR_ROLE = 'GENERIC'          # DIRECT_BGW / BEHIND_ASUS / GENERIC
RootDir = 'C:\NetDiag\V2_10' # reuse V2.10 storage/retention across upgrades
# Persistent files use RootDir\SENSOR_NAME; one writer per sensor/root.
RingBufferMinutes = 5
RingBufferMaxRecords = 20000    # independent RAM safety cap
RingBufferMaxMB = 32           # estimated payload bytes; PS objects add overhead
HealthySummaryIntervalSec = 60   # only persisted during formal incident by default
PersistPeriodicHealthCsv = $false  # healthy periods generate NO Health/Scheduler CSV
HeartbeatIntervalSec = 600      # compact liveness event in ordinary logs (not CSV)
CoordinatorGapThresholdSec = 15 # heartbeat/scheduler blind-period threshold
IdleSummaryIntervalSec = 300    # overwrite LIVE summary only every five healthy min
LogAdvisoryAssessmentChanges = $false  # throttle repetitive WATCH; first WATCH remains logged
AdvisoryLogCooldownSec = 300      # per code/endpoint start; use 900 for quieter history
IncidentPreMinutes = 5         # must be <= RingBufferMinutes
IncidentPostMinutes = 5        # after evidence-based recovery
IncidentTelemetryMaxMB = 256   # includes canonical + protocol CSVs per incident
StorageQuotaGB = 5            # all sensor runs, logs, captures and incident ZIPs
StorageReserveMB = 8          # reserved for state/status/fatal metadata
NormalLogMaxMB = 8            # rotate daily or at this size
HealthyRetentionDays = 30
EventRetentionDays = 90
IncidentRetentionDays = 30
PacketCaptureRetentionDays = 14
RunRetentionDays = 90          # old closed runs, only after evidence is pruned
StorageMaintenanceSec = 60
CompressClosedIncidents = $true
CompressAfterHours = 24        # background ZIP, only closed incidents
# Pushover keys are saved locally by SETUP_PUSHOVER.bat, never in this config.
EnablePushover = $true          # NOT_CONFIGURED until local keys are installed
PushoverSecretPath = ''        # blank: current user's LocalAppData\NetDiag
PushoverDevice = ''            # optional registered device name, blank = all
AlertIncidentDelaySec = 15     # confirmed fault must still be active after this hold
AlertCooldownSec = 60          # minimum between accepted notifications
AlertMaxPerHour = 12
AlertMaxPending = 24
AlertExpiryHours = 24          # bounded durable outbox; retries stop at this age
AlertRetryInitialSec = 30
AlertRetryMaxSec = 900         # backoff ceiling, 15 minutes
AlertRequestTimeoutSec = 10
AlertShutdownWaitSec = 5       # retain unsent items for next launch
AlertFaultCooldownSec = 3600   # suppress repeated storage-degradation notices
AlertIncidentPriority = 0      # 0 honors quiet hours; 1 bypasses them; never emergency
AlertRecoveryPriority = -1     # quiet recovery notification
AlertOnRecovery = $true
AlertFaultTypes = @('FATAL','RECORDER_LIMIT','STORAGE_WARNING','SENSOR_GAP')
InterfaceIndex = 0              # 0 selects lowest effective IPv4 route metric
GatewayIP = ''                  # blank uses selected interface's gateway
SystemDnsIP = ''                # blank uses selected interface's first IPv4 resolver
BgwManagementIP = '192.168.1.254'
EnableBgwProbe = $true          # applied only to DIRECT_BGW / BEHIND_ASUS
EnableRouterDnsProbe = $false   # opt in only if this device offers DNS service
EnableBgwDnsProbe = $false      # management reachability does not imply DNS service
EnableWebStatus = $true         # read-only, loopback only; no router/WAN exposure
WebStatusPort = 8765
WebStatusRefreshSec = 2
ExpectPublicDnsAnswers = $true  # detect nonpublic answers; not DNSSEC verification
AllowedPrivateDnsNames = @()    # exact names only, for deliberate split DNS/filtering
LanTargets = @()                # opt-in: @{ Name='AP'; IP='192.168.50.2' }
PreventIdleSleep = $true        # hold system awake; display may power off
SystemDnsRole = 'AUTO'          # AUTO / ROUTER / BGW / EXTERNAL
PingTimeoutMs = 900
PingConcurrency = 3             # allowed: 3 or 4
PingStaggerMs = 75              # allowed: 50..100
DnsTimeoutMs = 1800             # total transaction deadline, also for DNS-over-TCP
TcpConnectTimeoutMs = 1800
HttpsTimeoutSec = 6
EventDebounceSec = 2.0
RecoveryHoldSec = 5.0
EvidenceWindowSec = 25.0
CorrelationWindowSec = 12.0
SummaryIntervalSec = 45         # allowed: 30..60
DashboardIntervalMs = 750
EnablePacketCapture = $true
PacketCaptureSec = 60
PacketCaptureMaxMB = 128       # native circular ETL cap, never multi-file mode
PacketCaptureBytes = 128
CaptureCooldownSec = 120
TraceTimeoutMs = 700
TraceMaxHops = 20
TraceBudgetSec = 20
TraceTargets = @('1.1.1.1','8.8.8.8','9.9.9.9')
# Fixed-rate deadlines; missed slots are skipped, never queued/caught up.
# Each family has one worker; slower DNS/HTTPS/MTU/trace cannot block the UI.
Schedules = @{
    ICMP         = @{ IntervalSec=5;   PhaseMs=0;    Enabled=$true }
    DNS          = @{ IntervalSec=5;   PhaseMs=650;  Enabled=$true }
    TCP443       = @{ IntervalSec=10;  PhaseMs=1350; Enabled=$true }
    HTTPS        = @{ IntervalSec=20;  PhaseMs=2150; Enabled=$true }
    NIC          = @{ IntervalSec=10;  PhaseMs=3050; Enabled=$true }
    TCP_STATS    = @{ IntervalSec=10;  PhaseMs=3750; Enabled=$true }
    DNS_TRANSPORT= @{ IntervalSec=30;  PhaseMs=4550; Enabled=$true }
    MTU          = @{ IntervalSec=60;  PhaseMs=6050; Enabled=$true }
    TRACE        = @{ IntervalSec=900; PhaseMs=8250; Enabled=$true }
}
PublicTargets = @(
    @{ Name='Cloudflare-1'; IP='1.1.1.1'; Provider='Cloudflare'; Role='Public' },
    @{ Name='Cloudflare-2'; IP='1.0.0.1'; Provider='Cloudflare'; Role='Public' },
    @{ Name='Google-1';     IP='8.8.8.8'; Provider='Google'; Role='Public' },
    @{ Name='Google-2';     IP='8.8.4.4'; Provider='Google'; Role='Public' },
    @{ Name='Quad9-1';      IP='9.9.9.9'; Provider='Quad9'; Role='Public' },
    @{ Name='Quad9-2';      IP='149.112.112.112'; Provider='Quad9'; Role='Public' },
    @{ Name='OpenDNS-1';    IP='208.67.222.222'; Provider='OpenDNS'; Role='Public' },
    @{ Name='OpenDNS-2';    IP='208.67.220.220'; Provider='OpenDNS'; Role='Public' },
    @{ Name='AdGuard-1';    IP='94.140.14.14'; Provider='AdGuard'; Role='Public' },
    @{ Name='AdGuard-2';    IP='94.140.15.15'; Provider='AdGuard'; Role='Public' },
    @{ Name='Verisign-1';   IP='64.6.64.6'; Provider='Verisign'; Role='Public' },
    @{ Name='Verisign-2';   IP='64.6.65.6'; Provider='Verisign'; Role='Public' },
    @{ Name='Lumen-Level3'; IP='4.2.2.2'; Provider='Lumen'; Role='Public' }
)
DnsResolvers = @(
    @{ Name='ATT-Primary';   IP='68.94.156.1';     Class='ATT' },
    @{ Name='ATT-Secondary'; IP='68.94.157.1';     Class='ATT' },
    @{ Name='Cloudflare';    IP='1.1.1.1';         Class='Public' },
    @{ Name='Google';        IP='8.8.8.8';         Class='Public' },
    @{ Name='Quad9';         IP='9.9.9.9';         Class='Public' },
    @{ Name='OpenDNS';       IP='208.67.222.222'; Class='Public' }
)
DnsNames = @(
    'www.microsoft.com',
    'www.apple.com',
    'www.amazon.com',
    'www.cloudflare.com',
    'www.google.com',
    'www.github.com'
)
HttpsSites = @(
    @{ Name='Microsoft';  Provider='Microsoft'; Url='https://www.microsoft.com/' },
    @{ Name='Google';     Provider='Google'; Url='https://www.google.com/' },
    @{ Name='Apple';      Provider='Apple'; Url='https://www.apple.com/' },
    @{ Name='Cloudflare'; Provider='Cloudflare'; Url='https://www.cloudflare.com/' },
    @{ Name='Amazon-AWS'; Provider='Amazon'; Url='https://aws.amazon.com/' }
)
TcpConnectTargets = @(
    # Literal-IP controls run first, before any hostname resolver delays.
    @{ Name='Cloudflare-Pinned'; HostName='1.1.1.1'; Port=443; Provider='Cloudflare' },
    @{ Name='Google-Pinned'; HostName='8.8.8.8'; Port=443; Provider='Google' },
    @{ Name='Cloudflare'; HostName='www.cloudflare.com'; Port=443; Provider='Cloudflare' },
    @{ Name='Google';     HostName='www.google.com';     Port=443; Provider='Google' },
    @{ Name='Apple';      HostName='www.apple.com';      Port=443; Provider='Apple' },
    @{ Name='Amazon-AWS'; HostName='aws.amazon.com';      Port=443; Provider='Amazon' },
    @{ Name='GitHub';     HostName='github.com';          Port=443; Provider='GitHub' },
    @{ Name='Fastly';     HostName='www.fastly.com';      Port=443; Provider='Fastly' },
    @{ Name='Akamai';     HostName='www.akamai.com';      Port=443; Provider='Akamai' }
)
DnsTransportResolvers = @(
    @{ Name='ATT-Primary';   IP='68.94.156.1'; Class='ATT' },
    @{ Name='ATT-Secondary'; IP='68.94.157.1'; Class='ATT' },
    @{ Name='Cloudflare';    IP='1.1.1.1';     Class='Public' },
    @{ Name='Google';        IP='8.8.8.8';     Class='Public' },
    @{ Name='Quad9';         IP='9.9.9.9';     Class='Public' },
    @{ Name='OpenDNS';       IP='208.67.222.222'; Class='Public' }
)
MtuTargets = @(
    @{ Name='Cloudflare'; IP='1.1.1.1' },
    @{ Name='Google';     IP='8.8.8.8' }
)
MtuPayloadSizes = @(32,512,1200,1472)
}
