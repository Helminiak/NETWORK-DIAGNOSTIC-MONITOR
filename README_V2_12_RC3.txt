NETWORK DIAGNOSTIC MONITOR V2.12-RC3.1.1
Windows candidate / local network-status GUI / Merlin fork preparation

RC3.1.1 corrects the refused-socket self-test: it reserves a closed local port
and allows up to 5 seconds for the OS refusal, keeping live probe deadlines
unchanged. Nested socket errors retain their native codes and wrapper types.
Self-tests save Self_Test_Result.log, including actual refusal evidence. A
failure keeps exit code 1 and Fatal_Error.log, with the actual result and runtime.
Self-test errors now scroll normally instead of overwriting previous PASS lines.
Read RC3_1_1_SelfTest_Fix.md for the diagnosis and validation limits.

The October 4 run revealed public DNS names resolving to 10.0.0.1.
RC3 now distinguishes DNS wire success from public-answer usability and blocks
redirected named TCP connections before they can become false WAN evidence.
Read Longtest_RC3_1_Audit.md for the October 5-7 audit and RC3.1 corrections.
RC3_Log_Audit.md retains the earlier October 4 analysis.
RC3.1 fixes single-sample DNS confirmation, matched-query comparisons, and
traceroute claims; adds bounded DNS TCP fallback, failure/advisory totals,
process diagnostics, current PHY speed and honest HTTPS phase timings.
Launcher filenames remain RC3 for compatibility.
Set AdvisoryLogCooldownSec=900 for quieter history; the default remains 300.

QUICK START
1. Extract the entire package to a NEW folder on the Windows sensor PC.
2. Edit Monitor_Config.psd1. Set SENSOR_NAME and the verified SENSOR_ROLE.
   GENERIC is appropriate while topology is unverified. BEHIND_ASUS and DIRECT_BGW
   affect localization and BGW management probes. BGW management does not imply DNS.
3. Run SELF_TEST_V2_12_RC3.bat, then TEST_INTEGRATION.bat.
4. Stop the previous monitor with Q before reusing its sensor/root. One writer
   owns a sensor/root. RC3 keeps RootDir C:\NetDiag\V2_10 for retained-run continuity.
5. Run START_BACKGROUND.bat to hide the console and open network status.
   Initialization can take several seconds; the page retries until status is ready.
6. Reopen it with OPEN_STATUS.bat or http://127.0.0.1:8765/ on the sensor PC.
   Closing the page does not stop monitoring. STOP_BACKGROUND.bat requests a
   graceful shutdown of the supervisor and its owned child. The next manual
   background launch clears the deliberate stop marker.

For the traditional console, use START_V2_12_RC3.bat. ADMIN requests Windows
administrator rights explicitly, for optional pktmon capture. Hidden background
launch does not request elevation. Packet capture requires an elevated sensor
with pktmon installed. Do not run two launch modes for the same sensor/root.

BROWSER SETTINGS
EnableWebStatus = $true / $false
WebStatusPort = 8765                  allowed 1024..65535
WebStatusRefreshSec = 2              allowed 1..5
The server binds only IPv4 127.0.0.1; it requires no HTTP URL reservation.
If the port is occupied, the event log records WEB_STATUS_WARNING and monitoring
continues. Change the port and restart. The page has no cloud assets, configuration
editor, remote controls or arbitrary file-serving routes. Full screen and local
snapshot download are optional page actions. Missing/stale status remains unknown.
Multiuser hosts should treat localhost status as readable by local users.

NETWORK MAP SCOPE
The map covers the sensor, measured gateway, optional known LAN/BGW targets and
public-service observations. It does not discover all LAN clients, read ASUS WAN
counters, or infer physical switch/cable links. Add verified targets, for example:
LanTargets = @(
    @{ Name='Known-AP'; IP='192.168.50.2' }
)
Use the real device address. Maximum 16 LAN targets. A reply proves sensor-to-device
reachability only. Link speed is a PHY rate. RX/TX Mbps describe the sensor interface.
Baselines, resets and sampling gaps show unknown throughput rather than zero.

DNS INTEGRITY
ExpectPublicDnsAnswers = $true
AllowedPrivateDnsNames = @()   # exact names only, for deliberate filtering/split DNS
These tests expect public IPv4 answers for the configured public probe names.
Nonpublic/unsupported addresses are flagged; mixed public/private sets are flagged.
The wire status and returned addresses remain recorded. The check does not validate
DNSSEC or prove resolver identity. Exempt names deliberately and document why.
Private-answer name failures are separate from DNS transport failures and are not
counted as TCP attempts. Two literal public-IP TCP controls bypass DNS and run first.
A successful TCP connect is not an authenticated TLS or complete application test.
HTTPS rows use HEAD to measure response headers/TTFB while avoiding full page downloads.
A reply (including HTTP errors) proves endpoint response, not application success.
All sensor-interface traffic includes the monitor’s own probes.
DoH endpoint rows still measure reachability/timing, not validated DNS response bodies.

HEALTHY STORAGE / INCIDENT EVIDENCE
Detailed healthy observations stay in a bounded RAM ring. The default does not
create periodic healthy probe, Health or Scheduler CSV. Compact liveness logs,
configuration, overwritten summaries and supervisor control metadata still persist.
Formal incidents retain pre-event and active data; post-event time starts only
after fresh evidence-based recovery. Stopping an active incident does not recover it.
Partial traceroutes are included in readable Trace.csv during incident recording.
Normal ring expiry and capacity-pressure eviction are reported separately.
Status_Final.json is written at graceful/fatal finalization when the web server ran.
Use Package_Latest_Run_V2_12_RC3.bat to package logs. Pushover keys are excluded.

UNATTENDED STARTUP
Install_Startup_Task.ps1 / Supervise_Monitor.ps1 are the existing Windows 5.1
supervised path. Startup uses the same account as local DPAPI-protected Pushover keys;
Windows task credentials require the account password, not its sign-in PIN.
Task installation is optional, administrator-only and refuses to overwrite an
existing task. Review PRODUCTION_ACCEPTANCE.md and the installer's parameters
before registering a task. Closing/hiding a console does not itself install startup.
A deliberate StopSupervisor.txt marker keeps that supervisor stopped until the
next manual START_BACKGROUND clears it; OPEN_STATUS does not restart the monitor.

ALERTS
SETUP_PUSHOVER.bat installs local keys under the same Windows account.
No embedded credential is supplied. NOT_CONFIGURED means no phone delivery.
Existing durable retry, cooldown, expiry, hourly cap and priority behavior remains.

DIAGNOSTIC TEST
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Network_Diagnostic_V2_12_RC3.ps1 -Diagnostic -DurationSec 180 -NoDashboard -LogRoot C:\NetDiag\RC3_Lab
Diagnostic disables capture and Pushover. It still measures the host/network.
The integration script uses a disposable copy with declared native-probe adapters;
production sources are not replaced with mocks.

HISTORICAL REPLAY
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Replay_Run.ps1 -RunPath C:\ExtractedRun -OutputDir C:\ReplayOutput
Replay reads canonical incident CSV and creates historical status/timeline/results.
It does not recreate healthy rows that were never retained. AssertOctoberFixture
is only the packaged October 4 regression assertion, not a general replay option.
verification/historical-status.json and screenshots reflect the provided run.

MERLIN FORK OPTION
web/ contains reusable plain HTML/CSS/JavaScript. schema/ defines status JSON v1.
Windows APIs remain in the probe/deployment adapters. merlin/ contains a read-only
capability checker and a concrete fork plan using native router probes and WebUI
add-on integration. RC3 is not installable on Merlin as-is. Do not flash firmware
or copy Windows executables to a router. Exact model/revision/build and router
resource/authentication/soak tests are required for the port.

ROLLBACK / VERIFICATION
rollback/ preserves the exact RC2 source ZIP and original RC1 ZIP.
verification/ contains test results, replay evidence, schema checks and desktop/
mobile GUI screenshots. SHA256SUMS.txt covers the package files except itself.
PRODUCTION_ACCEPTANCE.md records native Windows and router tests still needed.
Portable PASS evidence does not close unobserved native release gates.
