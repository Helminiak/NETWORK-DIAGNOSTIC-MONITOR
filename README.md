# Network Diagnostic Monitor

Cross-platform network diagnostic monitoring project, currently centered on Windows with an explicit portability boundary for a future Asuswrt-Merlin implementation.

## Repository purpose

This repository exists to provide a controlled source of truth for the network monitor instead of maintaining multiple ambiguous ZIP/folder variants.

The system is intended to:

- continuously observe network health
- capture evidence only when useful
- distinguish LAN, gateway, DNS, ISP, and remote-path failure modes
- generate forensic-quality logs suitable for later analysis
- provide a local read-only status/dashboard layer
- support unattended operation
- retain a clean architectural path toward Asuswrt-Merlin

## Current state

The RC3 family is under active validation. Historical ZIP packages are treated as release artifacts, not authoritative working copies.

Going forward, identify a test candidate by branch/commit/tag, for example:

```text
repository + branch + commit SHA + release tag
```

rather than by local folder name alone.

## Intended architecture

The implementation should progressively separate platform-neutral diagnostic logic from OS-specific adapters:

```text
NETWORK-DIAGNOSTIC-MONITOR/
├── src/
│   ├── core/
│   ├── windows/
│   └── merlin/
├── adapters/
│   ├── windows/
│   └── asuswrt-merlin/
├── tests/
├── docs/
├── packaging/
│   ├── windows/
│   └── merlin/
└── releases/
```

The exact directory structure may evolve, but platform-neutral decision logic should not become unnecessarily coupled to PowerShell or Windows-only APIs.

## Windows scope

The Windows implementation may contain:

- PowerShell collectors and orchestration
- ICMP/TCP/DNS/path diagnostics
- self-tests
- health checks
- fault-triggered logging
- notification integrations
- local status/dashboard support
- installation/update scripts
- configuration templates

## Asuswrt-Merlin scope

The future Merlin implementation should reuse behavior and test vectors where practical while replacing Windows-specific dependencies with router-appropriate mechanisms.

Potential targets include:

- POSIX shell or lightweight compiled helpers where justified
- router-native scheduler/service integration
- low-storage logging policy
- interface/gateway discovery
- WAN-state observation
- DNS/path probes
- optional notification transport

A separate `asus-merlin-network-tools` repository may later be created if the router implementation develops an independent release lifecycle. Until then, the portability boundary should be maintained here.

## Change-control model

Preferred development flow:

```text
issue
  ↓
feature/fix branch
  ↓
implementation
  ↓
self-tests + regression tests
  ↓
pull request
  ↓
review
  ↓
merge
  ↓
version tag
  ↓
release artifact
```

A ZIP is an output artifact. A Git commit is the controlled source state.

## Public-repository hygiene

Do not commit:

- passwords, tokens, Pushover credentials, SMTP credentials, or private keys
- packet captures containing credentials/session material
- public IP or internal network inventory when not intentionally disclosed
- router backups containing secrets
- private certificates
- personal or unrelated documents

Commit sanitized logs and synthetic fixtures when test evidence is needed.

## Release requirement

A release candidate should be reproducible from source and should include automated verification of the parser, configuration loading, startup/shutdown behavior, expected network-failure classification, and packaging integrity before it is tagged.
