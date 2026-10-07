# Network Diagnostic Monitor

Current candidate: **V2.12-RC3.1.1**. This repository is the working source for
the Windows monitor, its local network-status GUI, and the future Asuswrt-Merlin
backend. Changes are identified by branch and commit SHA. Release ZIPs are built
from that source rather than edited independently.

The monitor samples independent network probe families, retains bounded
incident evidence, separates DNS-answer integrity from transport failures, and
publishes a read-only status page at `http://127.0.0.1:8765/` by default. Its map
covers the sensor, measured gateway, configured LAN targets and public probe
observations. It does not enumerate every LAN client or measure router WAN
counters.

## Run on Windows

1. Download a candidate artifact from a successful [Actions run](../../actions)
   or clone this repository at the specific candidate branch/commit.
2. Run `SELF_TEST_V2_12_RC3.bat`, then `TEST_INTEGRATION.bat`.
3. Keep machine settings separate from the tracked defaults:

   ```powershell
   New-Item -ItemType Directory -Force local | Out-Null
   Copy-Item Monitor_Config.psd1 local/Monitor_Config.psd1
   notepad local/Monitor_Config.psd1
   ```

   Set a unique `SENSOR_NAME` and verify `SENSOR_ROLE`. `GENERIC` avoids inferring
   ASUS/BGW ownership while topology is unverified. Configure the retained log
   root and optional LAN targets deliberately. Pushover keys are saved locally
   with `SETUP_PUSHOVER.bat`, under the same Windows account that runs the sensor.
4. Stop an earlier instance before starting the new candidate:

   ```powershell
   powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Launch_Background.ps1 -ConfigPath .\local\Monitor_Config.psd1
   ```

   This hides the console and opens the status page. Add `-NoBrowser` for hidden
   monitoring without opening a browser. Reopen the default page with
   `OPEN_STATUS.bat`; if a custom port is configured, use that configured URL.
   Closing the browser leaves monitoring active. Stop with `STOP_BACKGROUND.bat`
   when using the default configuration, or the matching custom configuration
   through `Stop_Background.ps1 -ConfigPath .\local\Monitor_Config.psd1`.

Windows PowerShell **5.1** is the monitor runtime. Python, Node.js and Playwright
are developer/build dependencies only. Packet capture needs an elevated native
Windows sensor and available `pktmon`; the hidden launcher does not request
elevation.

## Source and validation

- [CONTRIBUTING.md](CONTRIBUTING.md): branch, test and review workflow.
- [docs/source-control.md](docs/source-control.md): authoritative source and rollback.
- [SOURCE_IMPORT.json](SOURCE_IMPORT.json): SHA-256 provenance for the exact
  RC3.1.1 source import. Earlier RC3.1 is retained on `archive/rc3.1` and in Git
  history; import timestamps describe migration, not the original release date.
- [RC3_1_1_SelfTest_Fix.md](RC3_1_1_SelfTest_Fix.md): the short refused-socket test
  deadline, corrected failure reporting and remaining native acceptance limits.
- [PRODUCTION_ACCEPTANCE.md](PRODUCTION_ACCEPTANCE.md): native sensor and router
  acceptance gates. CI is an additional source/runtime check, not production approval.
- [merlin/README.md](merlin/README.md): shared status/web contract and port boundary.

The public fixtures use synthetic sensor identity, topology and observations.
Operational logs, packet captures and credentials stay with the sensor.

## Build a candidate

From a clean committed checkout, with Python 3.11 or later:

```sh
python tools/build_release.py
```

The allowlisted ZIP, SHA-256 sidecar and source-commit metadata appear under
`dist/`. The ZIP uses fixed metadata and stored entries for deterministic bytes
across supported Python platforms. `SHA256SUMS.txt` covers every packaged file
except itself. GitHub Actions builds twice and checks equality and coverage.
