"""Exercise the real self-test failure path in a disposable source copy.

Developer check only; Python and the supplied PowerShell runtime are not monitor
dependencies. Run with one argument: the absolute PowerShell executable path.
All native probe fixtures remain loopback-only. The final refusal result is
replaced with a declared TCP_TIMEOUT to verify that it is never accepted.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
runtime = Path(sys.argv[1]).resolve()
evidence = Path(__file__).resolve().parent
checks = []

def check(condition, name):
    if not condition:
        raise AssertionError(name)
    checks.append("PASS " + name)
    print(checks[-1])

with tempfile.TemporaryDirectory(prefix="netdiag-selftest-failure-") as temp:
    copy = Path(temp) / "Source"
    shutil.copytree(root, copy, ignore=shutil.ignore_patterns("rollback"))
    test_path = copy / "lib" / "Rc31SelfTest.ps1"
    source = test_path.read_text(encoding="utf-8-sig")
    needle = "$result=Invoke-TcpProbe '127.0.0.1' $port '' 500 $deadlineMs"
    check(source.count(needle) == 1, "Injection targets only the final loopback refusal result")
    replacement = "$result=@{Status='FAIL';Stage='TCP_TIMEOUT';TcpAttempted=$true;Ms=5000;Error=$null;IP='127.0.0.1';Port=$port;HostName='127.0.0.1'}"
    test_path.write_text(source.replace(needle, replacement), encoding="utf-8-sig")
    env = dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT="1", POWERSHELL_UPDATECHECK="Off")
    completed = subprocess.run(
        [str(runtime), "-NoLogo", "-NoProfile", "-File", str(copy / "Network_Diagnostic_V2_12_RC3.ps1"), "-SelfTest"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=90,
    )
    output = completed.stdout
    (evidence / "failure-injected-output.txt").write_text(output, encoding="utf-8")
    check(completed.returncode == 1, "A TCP deadline without a native refusal still fails with exit code 1")
    check("SELF-TEST STOPPED DUE TO A FAILED CHECK" in output and "MONITOR STOPPED DUE TO A FATAL ERROR" not in output, "Failed validation is labelled as a self-test failure")
    check('"Stage":"TCP_TIMEOUT"' in output and "Actual probe:" in output and "DeadlineMs=5000" in output, "The failed assertion prints the actual probe result and deadline")
    check("PS=" in output and "CLR=" in output and "OS=" in output, "Failure output identifies PowerShell, CLR and OS")
    fatal = (copy / "Fatal_Error.log").read_text(encoding="utf-8-sig")
    (evidence / "failure-injected-fatal.log").write_text(fatal, encoding="utf-8")
    check("SELF-TEST FAILURE" in fatal and '"Stage":"TCP_TIMEOUT"' in fatal, "Compatibility failure log retains the actual result")
    transcript = (copy / "Self_Test_Result.log").read_text(encoding="utf-8-sig")
    check("Actual probe:" in transcript and '"Stage":"TCP_TIMEOUT"' in transcript, "The transcript preserves evidence even after the terminal closes")

summary = "FAILURE REPORTING PASSED: " + str(len(checks)) + " checks; final timeout result deliberately injected, strict refusal assertion preserved."
print(summary)
(evidence / "failure-reporting-tests.txt").write_text("\n".join(checks + [summary]) + "\n", encoding="utf-8")
(evidence / "failure-reporting-result.json").write_text(json.dumps({"checks": len(checks), "injection": "Final local refusal result replaced with TCP_TIMEOUT", "expectedExitCode": 1, "actualExitCode": completed.returncode}, indent=2) + "\n", encoding="utf-8")
