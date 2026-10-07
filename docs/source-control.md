# Source authority and release history

The checked-out Git commit defines the source under discussion. Quote its full
SHA and the branch in reports and pull requests. The working tree is a single
program root; `lib/`, `web/`, `schema/`, `merlin/` and `verification/` are parts
of that same checkout.

The migration preserves three stages in separate commits:

1. An initial main-branch README makes the initially empty repository usable.
2. RC3.1's selected source is imported byte-for-byte, with its archive hash and
   per-file hashes. The `archive/rc3.1` branch retains this known earlier source.
3. RC3.1.1's correction is imported as a separate commit. Repository tooling,
   synthetic fixtures, CI and declared test-harness corrections follow in a
   separate commit. Those corrections limit Linux process-identity substitution
   to Linux, validate honest PARTIAL resource samples, and restrict parser checks
   to program/developer source rather than ignored settings or dependencies.

The import hashes in SOURCE_IMPORT.json remain an immutable record of the
original imported bytes. Subsequent Git diffs explain changes. The original
archives remain available as prior deliverables; copies of ZIP archives and
native operational logs are not committed into the source tree.

For a regression, inspect or check out the earlier commit in a separate clone or
worktree. Revert the responsible change through a reviewed commit. Record which
runtime and configuration produced the regression; a byte match alone does not
establish behavioral equivalence across Windows versions or router firmware.

The build uses a positive file allowlist, normalized ZIP metadata and a generated
SHA-256 manifest. BUILD_SOURCE.json inside the ZIP identifies the Git commit and
whether uncommitted development changes were allowed. Runtime logs and mutable
configuration do not enter the build through directory recursion.

CI exercises Windows PowerShell 5.1 on a hosted Windows runner, portable
PowerShell on Linux, declared integration adapters, pure state vectors, a
synthetic status-schema fixture and the real loopback web server/browser.
It does not establish the production sensor's topology, Wi-Fi behavior,
startup/reboot, packet-capture ownership, phone delivery or a 72-hour soak.
The Merlin directory is a port boundary and capability checker; it is not an
installed backend or router firmware image.
