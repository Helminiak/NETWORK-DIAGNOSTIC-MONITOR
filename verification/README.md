# Verification source and evidence boundaries

The complete self-test, actual coordinator integration with declared network
adapters, portable state vectors, deliberately failed self-test path and actual
loopback server/browser checks are reproducible from this Git checkout.
GitHub Actions uploads fresh results with the source commit. Generated outputs
and screenshots stay outside tracked source.

`historical-status.json` is a **synthetic** stopped/unresolved DNS-integrity
fixture. Its sensor name, gateway, timestamps, probe identifiers and topology
are constructed test values. It is not a published native run or an operational
network snapshot. `core-rc31.json` supplies language-neutral expected state
transitions for the current classification model and future Merlin backend.

The original RC3.1.1 deliverable produced 233 portable self-test passes, 11
adapted integration passes, 29 actual server/browser checks, 7 state transitions
and 7 injected-failure checks. The repository suite can include additional
parser checks for new developer PowerShell files. Windows DPAPI is skipped on
Linux; Windows native runtime checks must identify their OS/build/PowerShell.
Prior archives retain the earlier evidence. This repository does not relabel
portable or synthetic observations as native production-network evidence.

The Windows job requires Desktop PowerShell 5.1 and exercises native process
identity within the otherwise declared integration fixture. The Linux job uses
an explicit process-identity adapter. Neither replaces native deployment,
topology, reboot, capture, notifications, fault injection or the 72-hour soak.
