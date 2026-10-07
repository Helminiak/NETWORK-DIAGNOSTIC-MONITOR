# Repository working rules

- Treat the checked-out Git commit and branch as the current source. Before
  editing, report the branch, HEAD and working-tree state. Historical ZIPs are
  provenance and rollback references, not an alternate working tree.
- Work on a named feature or fix branch. Make changes reviewable through a pull
  request. Record the final commit SHA with validation results.
- Read README.md, CONTRIBUTING.md, PRODUCTION_ACCEPTANCE.md and the relevant
  module before changing behavior. Keep fixes separate from source imports.
- Preserve Windows PowerShell 5.1 compatibility, UTF-8 BOMs and the existing RC3
  launcher names. The status server remains read-only on IPv4 loopback.
- Keep local configurations, credentials, run logs, packet captures, diagnostic
  exports, build ZIPs and machine-identifying evidence outside tracked source.
  Use synthetic fixtures for public regression tests.
- Run tools/Test-Candidate.ps1 for PowerShell changes and the affected GUI/schema
  checks for browser or status-contract changes. Build with tools/build_release.py.
  Never describe Linux adapters or synthetic replay as a Windows/router pass.
- Use monotonic time and advancing independent observations for confirmation
  and recovery. Unknown/stale/missing measurements must not become zero or OK.
- Keep platform-specific probes in adapters. A Merlin implementation should
  reuse web assets, status schema and golden state vectors, preserve existing
  router hooks, and establish model/build/resource limits before installation.
- Keep native sensor, topology, reboot/startup, notification, real-fault and soak
  acceptance separate from CI. Do not mark a production release solely because
  automated checks pass.
