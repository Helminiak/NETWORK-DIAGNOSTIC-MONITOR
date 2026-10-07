# RC3.1.1 refused-socket self-test correction

The supplied RC3.1 Windows console output reports a failed assertion:
`Actual refused socket retains its native error instead of a generic TCP label`.
The launcher returns exit code 1. The output does not include the actual probe
result, Windows build, PowerShell version, or the complete failure log.

## Diagnosis and confidence

The strongest inference is a self-test deadline mismatch. An earlier closed-port
test allows `TCP_ERROR` **or** `TCP_TIMEOUT` with a 300 ms deadline. The final test
requires `TCP_ERROR`, `ConnectionRefused`, and a native error code with only
500 ms. If asynchronous connection completion has not arrived before that
deadline, the probe correctly returns `TCP_TIMEOUT` without a native exception,
and the final assertion fails. This branch follows directly from the source.
It cannot be confirmed as this user's exact result from the supplied text alone.

The original exception extractor successfully unwraps a normal PowerShell
invocation wrapper on the available Linux/PowerShell 7.4.6 runtime. There is no
evidence here establishing a Windows-specific `GetBaseException()` defect.
Extraction is nevertheless improved to walk a bounded inner-exception chain
directly and retain wrapper types for diagnosis.

The garbled suffixes are consistent with another definite source defect: the
outer error handler resets the console cursor to `(0,0)` even for scrolling
self-test output. It rewrites previous PASS rows without clearing their tails.
This correction removes that cursor reset during self-tests. The supplied text
does not establish damaged files or a network outage.

| Weakness | Correction |
| --- | --- |
| Final check expects an OS refusal within 500 ms | Allow up to 5,000 ms for this test only; still require an actual socket refusal and native code |
| Test releases its temporary port before probing | Keep an exclusive socket bound on IPv4 loopback without listening until the test completes |
| Failure text omits the result | Print the actual structured probe, target port, deadline, PowerShell, CLR and OS |
| Wrapped errors have little diagnostic context | Preserve native socket data and wrapper/inner types; cap traversal at 32 nodes and messages at 256 characters |
| Failure output overwrites earlier console rows | Let self-test errors scroll normally; label them as validation failures |
| Evidence is lost when the terminal closes | Save a fresh `Self_Test_Result.log`; keep `Fatal_Error.log` for compatibility, with a self-test label |
| Failed tests enter the monitor's notification path | Suppress runtime fatal notifications for self-test failures |

## Validation

| Check | Result and limits |
| --- | --- |
| Complete self-test | **233 PASS**, exit 0, on Linux with PowerShell 7.4.6; Windows DPAPI is explicitly skipped |
| Actual reserved loopback refusal | `TCP_ERROR`, `ConnectionRefused`, native Linux code `111`, with the PowerShell invocation wrapper retained |
| Nested invocation wrappers | Native socket type, enum and platform code survive nested PowerShell/reflection wrappers |
| Typed deadline exception | No native refusal or socket code is fabricated |
| Deliberately injected final `TCP_TIMEOUT` | **7 PASS** checking failure reporting; actual main script exits 1, preserves the strict assertion, identifies runtime, and saves evidence in both logs |
| Actual coordinator integration | **11 PASS**; native device/probe adapters and Linux process identity are explicitly simulated |
| Read-only server and browser | **29 PASS** with the actual C# loopback server and headless Chromium; historical and synthetic UI fixtures, security, stale/offline and mobile checks |
| Portable classification contract | **7 PASS** state transitions; no native APIs or network |
| Native Windows RC3.1.1 | **PENDING**; neither this fix nor the portable results certify Windows acceptance |

Evidence is under `verification/selftestfix/`. The failure injection is declared
and isolated in a disposable copy; the delivered source retains the real probe.
Earlier RC3.1 and RC3 verification directories are historical evidence, not
current Windows passes. The exact previous RC3.1 archive is in `rollback/`.

## Rerun on the Windows sensor

1. Extract this complete RC3.1.1 package into a new folder.
2. Run `SELF_TEST_V2_12_RC3.bat`. It should finish with exit code 0. Windows DPAPI
   may add a native check to the portable count.
3. Run `TEST_INTEGRATION.bat` before beginning a new monitoring run.
4. If the self-test fails, retain the complete `Self_Test_Result.log` and
   `Fatal_Error.log` from that new folder. They now show whether the failure was
   a deadline, a different socket error, or extraction of a wrapped exception.

Continue with the configured sensor role and log root. `START_BACKGROUND.bat`
hides the console and opens the read-only network status page;
`OPEN_STATUS.bat` reopens it at the configured local port (default
`http://127.0.0.1:8765/`). `STOP_BACKGROUND.bat` requests a graceful stop.
The Merlin fork boundary, portable state vectors, status schema and shared web
assets remain available. No router backend is installed by this correction.

## Technical references

Microsoft documents [inner exception wrappers](https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-exceptions)
and the [overridable `Exception.GetBaseException()` method](https://learn.microsoft.com/en-us/dotnet/api/system.exception.getbaseexception?view=netframework-4.8.1).
These explain the diagnostic approach; they do not establish the user's exact
failure cause.
