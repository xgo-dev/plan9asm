"""Script delegation checks; historical loop RED remains in Git history.

The actual process/source/object regressions live in internal/goasmoracle and
cmd/plan9asmgooracle, so the script and root tests consume one classifier.
"""

import pathlib
import contextlib
import json
import os
import signal
import subprocess
import tempfile
import unittest


class ARM64Plan9OracleScriptTests(unittest.TestCase):

    def test_actual_bash_cli_delegation(self):
        # This is a controlled Bash delegation regression, not a stock-Go or
        # source-rejection certificate. Execute the script's exact fragment.
        script = (pathlib.Path(__file__).resolve().parent / "check-arm64-plan9-corpus.sh").read_text()
        start = script.index('"$go_path" run "$repo_root/cmd/plan9asmgooracle"')
        end = script.index('\naccepted_cases=', start)
        fragment = script[start:end]
        with tempfile.TemporaryDirectory(prefix="decoder-delegation-") as directory:
            output = pathlib.Path(directory) / "argv"
            environment = os.environ.copy()
            environment.update({"go_path": "delegate", "repo_root": "/fixture repository",
                                "source_cases": "/fixture cases", "family_file": "/fixture families",
                                "goroot": "/fixture SDK", "oracle_parent": "/fixture report",
                                "capture": str(output)})
            program = 'set -euo pipefail\ndelegate() { printf "%s\\0" "$@" >"$capture"; }\n' + fragment
            child = subprocess.Popen(["/bin/bash", "-c", program], env=environment,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            pgid = os.getpgid(child.pid)
            try:
                stdout, stderr = child.communicate(timeout=5)
            finally:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(pgid, signal.SIGKILL)
                child.wait(timeout=2)
            try:
                os.killpg(pgid, 0)
                absent = False
            except ProcessLookupError:
                absent = True
            argv = output.read_bytes().split(b"\x00")[:-1]
            record = {"role": "controlled-Bash-delegation", "pid": child.pid, "pgid": pgid,
                      "waited": True, "group_absent": absent, "exit": child.returncode,
                      "argv": [arg.decode() for arg in argv], "fragment": fragment,
                      "stdout": stdout.decode(), "stderr": stderr.decode()}
            evidence = os.environ.get("PLAN9ASM_ORACLE_EVIDENCE_DIR")
            if evidence:
                with (pathlib.Path(evidence) / "bash-delegation.json").open("x") as stream:
                    json.dump(record, stream, indent=2)
                    stream.write("\n")
            self.assertTrue(absent, "controlled Bash group not closed")
            self.assertEqual(child.returncode, 0, record)
            self.assertEqual(record["argv"], ["run", "/fixture repository/cmd/plan9asmgooracle",
                                           "-cases=/fixture cases", "-families=/fixture families",
                                           "-go=delegate", "-goroot=/fixture SDK",
                                           "-out=/fixture report/go-oracle"])

    def test_shared_owner_and_retained_reports(self):
        script = (pathlib.Path(__file__).resolve().parent / "check-arm64-plan9-corpus.sh").read_text()
        for expected in ('/cmd/plan9asmgooracle"', '-go="$go_path" -goroot="$goroot"',
                         'accepted_cases="$oracle_parent/go-oracle/accepted.txt"',
                         'full_report="$oracle_parent/full.json"',
                         'accepted_report="$oracle_parent/accepted.json"'):
            self.assertIn(expected, script)
        for forbidden in ("subprocess.DEVNULL", "subprocess.run", "else rejected"):
            self.assertNotIn(forbidden, script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
