# Asuswrt-Merlin fork option

RC3 remains a **Windows sensor**. Neither PowerShell nor pktmon is a native Merlin dependency. This directory is a fork starting point, not router-ready monitoring software or a firmware image.

The shared pieces are `../web/` (plain HTML/CSS/JavaScript), `../schema/status.v1.schema.json` and the platform-neutral observation/state definitions in `../lib/Core.ps1` and `AddressPolicy.ps1`. The browser has no Windows API, console, cloud service, Node.js or framework dependency. A router backend can emit the same JSON contract; it does not need to run PowerShell. Keep Windows as a separate client-path sensor after porting.

## Before selecting a port target

Run `sh probe-capabilities.sh` on the intended router over an already authorized local session. The script only reads a small whitelist of model/build values, architecture, RAM and command availability. It makes no network requests or persistent changes. Supply the resulting JSON together with the precise router hardware revision. An advertised add-ons API does not prove the firmware is supported or that a probe tool has the needed options. Check the exact model against Merlin's supported-device list. Do not install a firmware image selected by model family alone.

## Fork design

| Boundary | Windows RC3 | Merlin branch to implement |
| --- | --- | --- |
| Probe adapters | Windows route/NIC, .NET sockets, curl, tracert, pktmon | BusyBox-compatible probes plus a small compiled worker where deadlines, DNS parsing or JSON cannot be bounded reliably in shell |
| State/classification | Fresh observations, public-answer policy, independent provider/protocol evidence, monotonic debounce/recovery | Equivalent implementation checked against the same golden fixtures and recorded replay; no shell `sleep` duration treated as clock truth |
| Status page | Loopback-only C# listener and reusable assets | Authenticated router WebUI add-on using the Addons API; deliver data through a verified authenticated route on the specific build |
| Topology | Sensor/gateway/opt-in LAN targets; full inventory unknown | DHCP leases/ARP/IPv6 neighbors/bridge and wireless client observations with source and age; configured links distinguished from discovered links |
| Traffic | Selected laptop interface delta Mbps | Router WAN-interface deltas, resets and route changes; test offload accounting before claiming WAN totals |
| Persistence | Quota-controlled incident files and RAM ring | Program/config on JFFS; sampling/status/RAM ring in `/tmp`; bounded incident logs on suitable USB storage; avoid per-sample flash writes |
| Lifecycle | Windows supervisor and startup task | Namespaced service called by `services-start`, single-instance ownership, bounded restart backoff and explicit uninstall; preserve other add-ons and existing hooks |
| Capture | Owned pktmon session and bounded ETL | Optional tcpdump with verified interface/filter, bounded RAM/storage and per-process ownership; test CPU load and forwarding impact |

The official `services-start` hook and Addons API provide extension points without maintaining an entire custom firmware image. Prefer an add-on branch first. Forking Merlin's firmware source itself is a separate build/release undertaking.

Set router resource limits from measurement. Initial engineering targets: at most 8 MiB of raw ring payload, at most 120 traffic points, at most 256 KiB status response, bounded worker count, and explicit CPU/RAM/storage budgets under load. These are proposed targets, **not measured compatibility claims**. RC3 Windows defaults are not a router memory profile.

## Required router tests

1. Exact model/build/architecture discovery and install/uninstall preserving every existing JFFS hook.
2. Authentication: anonymous and cross-origin access denied, no WAN listener, no new firewall opening, no credentials in exported JSON.
3. Interface mapping including PPPoE/VLANs/dual-WAN/VPN, IPv6 behavior, acceleration counters and counter resets; route changes update topology without inventing health.
4. Private-answer/captive-portal/filtering fixtures, pinned controls, complete verified encrypted DNS transaction, fresh recovery and stale-data handling.
5. Reboot, WAN reconnection, service crash, storage full/USB missing, time correction and quota protection.
6. 72-hour load/soak: idle/busy forwarding throughput, CPU, RAM, temperature and flash-write count. Router-side monitoring cannot observe a powered-off router; an external sensor remains necessary.

## Primary references checked for this candidate

- [Merlin user scripts](https://github.com/RMerl/asuswrt-merlin.ng/wiki/User-scripts)
- [Merlin Addons API](https://github.com/RMerl/asuswrt-merlin.ng/wiki/Addons-API)
- [Supported devices](https://github.com/RMerl/asuswrt-merlin.ng/wiki/Supported-Devices)

No router hooks, firmware, firewall settings, NVRAM values or WebUI pages have been installed by this package.

## RC3.1 portable regression boundary

Use `../verification/fixtures/core-rc31.json` as golden DNS state vectors when implementing the router backend. The Windows reference harness is `Test_Portable_Contract.ps1`; a Merlin engine should consume the same inputs and match codes/actions/active state. Success/failure clocks are separate, and proxy comparisons require the same name and transport. Status-v1 optional process diagnostics may be omitted or UNMEASURED/PARTIAL when unsupported; never insert zero counters to satisfy a dashboard. CPU 100% denotes one logical CPU and excludes child processes. Windows cadence, PowerShell memory and disk retention settings remain unsuitable as unmeasured router defaults.
