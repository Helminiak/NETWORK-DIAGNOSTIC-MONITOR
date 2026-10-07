# Development and review

Clone the repository and work from a named branch based on the selected Git
commit. Use `fix/<topic>`, `feature/<topic>`, or `merlin/<topic>` for future work.
Include the base and final commit SHAs when discussing changes. After the import
pull request is accepted, main is the reviewed source branch; candidate files
should be changed in this repository and packaged from commits.

Keep local sensor settings under the ignored `local/` directory and pass them
through `-ConfigPath`. Never commit credentials, capture files, native run logs
or machine identifiers. Public tests should contain synthetic data or an
explicitly approved anonymized fixture. Preserve UTF-8 BOMs in imported
PowerShell files; Windows PowerShell 5.1 uses those BOMs when decoding non-ASCII
text.

## Checks

On native Windows PowerShell 5.1:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-Candidate.ps1 -RequireWindows51
```

On an installed PowerShell 7 runtime for portable logic checks:

```sh
pwsh -NoLogo -NoProfile -File tools/Test-Candidate.ps1 -PowerShellPath /absolute/path/to/pwsh
```

The self-test uses local loopback fixtures. Integration uses declared synthetic
network/device adapters; native Windows process identity is exercised on
Windows, while Linux uses an explicitly labelled adapter. Neither performs a
production-network fault injection or validates startup, reboot, packet capture
or a router installation.

For the browser and schema fixtures, install the lockfile's dependencies with
`npm ci`, install Playwright Chromium, and set `NETDIAG_TEST_PWSH` and
`NETDIAG_TEST_CHROME` to the test executables. Run `npm run test:web` and
`python verification/validate_evidence.py` with jsonschema installed. Test output
and screenshots are ignored. The core-port state vectors run through
`verification/Test_Portable_Contract.ps1`.

## Packaging and approval

`tools/build_release.py` packages only explicit paths in `release-files.json`
and requires a clean committed checkout. It records the commit, creates a full
manifest, uses deterministic ZIP metadata, and excludes operational evidence.
Use `--allow-dirty` only for a clearly labelled development build. Verify two
identical builds with `python tools/verify_release.py dist/<candidate>.zip`.

Describe the trigger, resulting behavior, relevant tests and remaining native
gates in the pull request. Recommended main-branch required checks are
`Windows PowerShell 5.1`, `Portable PowerShell`, and `Web and package`. Those
checks must be enabled in repository branch rules to become enforced merge
requirements; this import does not change repository administration settings.
Successful CI is not approval to publish a production release. Record the sensor
OS/PowerShell/build, source SHA, native gate results and a witnessed soak in
PRODUCTION_ACCEPTANCE.md before a production designation.
