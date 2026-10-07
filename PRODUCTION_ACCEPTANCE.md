# RC3.1.1 native acceptance record

RC3.1.1 is a candidate. The user reported a native RC3.1 refused-socket self-test
failure; its correction and current portable evidence are recorded in
RC3_1_1_SelfTest_Fix.md and verification/selftestfix/. Native RC3.1.1 sensor
deployment remains pending. Hosted Windows 5.1 CI now passes the source suite;
that evidence is recorded below. Portable tests/replay are evidence for specific logic, not a
substitute for the Windows or router runs below. The October 4 upload came from
RC2. The October 5-7 longtest identifies RC3 and provides about 58h of native
manual execution, one gap, graceful closure and one bounded pktmon capture.
It does not provide a code hash, native self-test/startup/reboot evidence,
process resource trends, or a complete 72h gate. All RC3.1 edits still need
native Windows acceptance; portable evidence is in the original archived deliverable and current CI artifacts.

| Gate | Required observed behavior | Current evidence |
| --- | --- | --- |
| W01: Windows 5.1 parse/self-test | Full extracted current candidate passes under native Windows PowerShell 5.1; no ambient mocks | RC3.1.1 hosted Windows 5.1 source suite: 235 PASS, including native refusal/error 10061 and DPAPI. Exact source/run below. Extracted candidate and production sensor checks are separate gates; CI also checks the extracted ZIP on subsequent commits. |
| W02: healthy execution | All enabled native families advance at configured cadence; no healthy probe/Health/Scheduler CSV by default | RC2 real run has 4,602 ICMP/DNS sweeps and zero skips for those families; RC3 stubbed integration passed; native RC3 NOT RUN |
| W03: topology | Verified role/gateway/interface/DNS; deliberate route, VPN/default metric and DNS changes become warnings; no false ownership; BGW probes only for verified role | RC2 GENERIC correctly disables explicit BGW; RC3 native change detection NOT RUN |
| W04: hidden launch/startup | Background start opens local page without retained console; browser close preserves child; reopen works; correct-account task survives reboot before desktop login | Source/server checks passed; native launch/task/reboot NOT RUN |
| W05: ownership/recovery | Kill/freeze child, kill supervisor, duplicate foreground/supervisor attempt; only owned PID/start identity stopped, one writer and bounded restart | Hosted Windows integration passes native PID/start ownership against a real child; Linux declares its identity adapter. Production supervisor/duplicate/reboot acceptance NOT RUN |
| W06: power/console | Display sleeps while system keeps sampling; console selection cannot silently halt it; deliberate sleep/coordinator pause creates gap/skips without WAN inference | RC2 run has no reported gaps; native RC3 deliberate tests NOT RUN |
| W07: clocks/resume | Civil-clock changes do not affect debounce/rolling status; in-flight resume has bounded budget and old rows cannot confirm/recover | Portable fixtures passed; native RC3 NOT RUN |
| W08: real faults | Private DNS answers remain wire-success/integrity-fault; no redirected socket attempts; pinned controls remain independent; clean advancing answers recover; single-provider ICMP stays advisory | Recorded 5,362-row replay and semantic fixtures passed; native isolated-lab RC3 NOT RUN |
| W09: capture | Owned bounded pktmon starts/stops; forced kill/resume preserves uncertain capture and reservation; remediation never globally stops another session | RC2 capture stopped with exit 0/status no event loss; packet contents not decoded; native RC3 forced-shutdown NOT RUN |
| W10: storage | Real NTFS quota/limits/retention/compression/exporter/disk-full permissions; active evidence protected; capacity pressure visible; no uncontrolled growth | Portable fixtures passed; RC2 reports no suppressed writes/pruning; native fault-injection NOT RUN |
| W11: notifications | Same-account DPAPI round-trip and actual phone onset/recovery/gap; bounded outbox/rate/expiry and no secrets in export | Hosted Windows DPAPI synthetic-key round-trip PASS; portable queue tests PASS. Production sensor account and actual phone delivery NOT RUN; uploaded run NOT_CONFIGURED |
| W12: 72-hour soak | Independent wall-clock witness; native awake sampling, completion/skip reconciliation, bounded RAM/disk/CPU, classified gaps/restarts | Only RC2 approximately 6 h 23 min observed; RC3 72-hour NOT RUN |
| W13: browser on Windows | Local C# compile/bind under Windows 5.1; chosen port conflict nonfatal; stale backend cannot appear live; responsive supported-browser UI and no remote assets | Actual loopback server + headless Chromium and mobile viewport passed on Linux; native Windows NOT RUN |
| M01: Merlin target | Exact model/revision/build supported; discover capabilities and permissions; authenticated WebUI, native probes, interface/offload/flash accounting and 72-hour load/soak | Read-only checker tested on Linux fixture only; router model unspecified; router implementation NOT BUILT |

Record tester, UTC start/end, exact source SHA-256 manifest, OS/build, PowerShell,
sensor account/configuration, pass/fail and evidence paths for each native gate.
Keep candidate status until required deployment gates are actually observed.

## Hosted CI evidence

[Actions run 37675275684](https://github.com/Helminiak/NETWORK-DIAGNOSTIC-MONITOR/actions/runs/37675275684)
tested source commit `2cfd11d427d9e9b75e92786ce65261d484c252e0` on October 7, 2026.
All three jobs passed. Windows Server 2022 used Windows PowerShell
5.1.20348.5622 / Desktop and CLR 4.0.30319.42000: 235 self-test checks,
11 coordinator/ownership checks with explicitly simulated network/device
adapters, and 7 pure state transitions. Its actual loopback refusal preserved
`ConnectionRefused`, native error 10061 and the PowerShell wrapper; the first
native run measured about 2 seconds, exceeding the original 500 ms test deadline.
Linux separately passed 234 self-test checks, 7 deliberately injected failure
reporting checks, the schema fixture, and 29 actual C# server/Chromium checks.
Two independent candidate builds had identical bytes and complete manifests.

These observations establish the listed source/runtime checks on hosted
runners. They do not establish the production sensor's native network adapters,
GUI launcher, scheduled task, router deployment or 72-hour soak. Later commits
must pass their own CI checks; inspect the run's exact head SHA and artifacts.

## Reconciliation

For each schedule epoch:

- ScheduledSlots = ScheduledStarts + Skipped.
- Started = ScheduledStarts + RequestedStarts.
- Started = Completed + Aborted + Failed + InFlight (InFlight is 0 or 1).

Missed/busy slots may occur during suspension or slow sweeps; count and explain
them, never replay deadlines in a burst. Coordinator gaps are not necessarily
identical to all-worker blind periods, since workers can progress independently.
An active incident is not recovered by shutdown, a closed file, missing samples,
wire-success redirected answers, a successful different transport, or a stale page.

## Focused next run

Use an isolated test root and lab DNS responder, not intentional disruption of the
production WAN. Verify native Windows background/status behavior first, then
exercise redirected answers and pinned controls, route/DNS changes, graceful stop,
capture/export and notifications. Decode the provided ETL separately. After these
pass, perform the supervised 72-hour soak and choose an exact Merlin port target.

## Additional RC3.1 gates

- W14 resources: measure native Windows working set/private bytes/managed heap and CPU across at least 72h, including curl/tracert child cost separately. Unknown OS counters must remain null; resident memory should stabilize after ring churn.
- W15 DNS regression: isolated repeated and single proxy failures; matched names/transports; UDP truncation with TCP fallback under the original deadline; no socket use after nonpublic answers.
- W16 timing/recording: capture raw curl timestamps, preserve unknown phases, and measure incident flush/coordinator latency on the real disk.

The native RC3 longtest is partial supporting evidence for W02/W06/W09/W12, not an automatic PASS for the rows above.
