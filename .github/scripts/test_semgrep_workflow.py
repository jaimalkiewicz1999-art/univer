"""Execute the workflow's real shell steps with controlled scanner outcomes.

Requires the ruamel.yaml dependency installed with Semgrep. These are wrapper
regressions, not evidence of a real source scan or GitHub SARIF ingestion.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from ruamel.yaml import YAML


parser = argparse.ArgumentParser()
parser.add_argument(
    "--workflow",
    type=Path,
    default=Path(__file__).resolve().parents[1] / "workflows/security-semgrep.yml",
)
arguments, unittest_arguments = parser.parse_known_args()
workflow = YAML(typ="safe").load(arguments.workflow.read_text(encoding="utf-8"))
steps = workflow["jobs"]["semgrep"]["steps"]
scan_script = next(step["run"] for step in steps if step.get("id") == "semgrep")
gate_script = next(
    step["run"]
    for step in steps
    if step["name"] == "Fail on Semgrep error findings or execution errors"
)
summary_script = next(
    step["run"] for step in steps if step["name"] == "Summarize Semgrep report"
)
helper_path = Path(__file__).resolve().with_name("semgrep_sarif.py")


def report(*, successful=True, level=None, rules=None, results=None):
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Controlled test scanner", "rules": rules or []}},
            "invocations": [{"executionSuccessful": successful}],
            "results": results if results is not None else ([] if level is None else [{"level": level}]),
        }],
    })


class SemgrepWorkflowTests(unittest.TestCase):
    def execute(self, *, output, scanner_exit=0, installed=True, expected_counts=None):
        with tempfile.TemporaryDirectory(prefix="semgrep-workflow-test-") as directory:
            root = Path(directory)
            binaries = root / "bin"
            binaries.mkdir()
            helper_copy = root / ".github/scripts/semgrep_sarif.py"
            helper_copy.parent.mkdir(parents=True)
            shutil.copyfile(helper_path, helper_copy)
            scanner = binaries / "semgrep"
            scanner.write_text(
                f"#!{sys.executable}\n"
                "from pathlib import Path\n"
                "Path('scanner-called').touch()\n"
                f"output = {output!r}\n"
                "if output is not None:\n"
                "    Path('reports/semgrep.sarif').write_text(output, encoding='utf-8')\n"
                f"raise SystemExit({scanner_exit})\n",
                encoding="utf-8",
            )
            scanner.chmod(0o755)
            environment = os.environ.copy()
            environment.update({
                "PATH": str(binaries) + os.pathsep + environment["PATH"],
                "INSTALL_OUTCOME": "success" if installed else "failure",
                "GITHUB_OUTPUT": str(root / "outputs"),
                "GITHUB_STEP_SUMMARY": str(root / "summary"),
                "SARIF_UPLOAD_OUTCOME": "success",
            })
            scan = subprocess.run(
                ["bash", "-e", "-o", "pipefail", "-c", scan_script],
                cwd=root, env=environment, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(scan.returncode, 0, scan.stderr)
            outputs = dict(
                line.split("=", 1)
                for line in (root / "outputs").read_text(encoding="utf-8").splitlines()
            )
            environment["SEMGREP_EXIT_CODE"] = outputs["exit_code"]
            # Render the same shared helper used by the real summary and gate.
            summary = subprocess.run(
                ["bash", "-e", "-o", "pipefail", "-c", summary_script.replace("${{ github.run_id }}", "controlled-test")],
                cwd=root, env=environment, capture_output=True, text=True, timeout=15,
            )
            if expected_counts is not None:
                self.assertEqual(summary.returncode, 0, summary.stderr)
                rendered = (root / "summary").read_text(encoding="utf-8")
                for level, count in expected_counts.items():
                    self.assertIn(f"- {level.title()}: {count}\n", rendered)
            gate = subprocess.run(
                ["bash", "-e", "-o", "pipefail", "-c", gate_script],
                cwd=root, env=environment, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual((root / "scanner-called").exists(), installed)
            return gate.returncode

    def test_missing_report_is_a_scan_failure(self):
        self.assertEqual(self.execute(output=None), 2)

    def test_empty_report_is_a_scan_failure(self):
        self.assertEqual(self.execute(output=""), 2)

    def test_explicit_failed_invocation_is_a_scan_failure(self):
        self.assertEqual(self.execute(output=report(successful=False)), 2)

    def test_install_failure_does_not_run_scanner(self):
        self.assertEqual(self.execute(output=None, installed=False), 2)

    def test_scanner_error_code_is_preserved(self):
        self.assertEqual(self.execute(output=report(), scanner_exit=7), 7)

    def test_error_finding_fails_existing_gate(self):
        self.assertEqual(self.execute(output=report(level="error")), 1)

    def test_warning_finding_preserves_existing_policy(self):
        self.assertEqual(self.execute(output=report(level="warning")), 0)

    def test_valid_zero_finding_report_passes(self):
        self.assertEqual(self.execute(output=report()), 0)

    def test_malformed_report_fails(self):
        self.assertNotEqual(self.execute(output="invalid SARIF"), 0)

    def test_inherited_rule_error_fails_gate_and_appears_in_summary(self):
        self.assertEqual(self.execute(
            output=report(rules=[{"id": "critical-rule", "defaultConfiguration": {"level": "error"}}],
                          results=[{"ruleId": "critical-rule"}]),
            expected_counts={"error": 1, "warning": 0, "note": 0, "other": 0},
        ), 1)

    def test_explicit_result_level_overrides_rule_default(self):
        self.assertEqual(self.execute(
            output=report(rules=[{"id": "critical-rule", "defaultConfiguration": {"level": "error"}}],
                          results=[{"ruleId": "critical-rule", "level": "note"}]),
            expected_counts={"error": 0, "note": 1},
        ), 0)

    def test_rule_index_resolves_inherited_error(self):
        self.assertEqual(self.execute(
            output=report(rules=[{"id": "critical-rule", "defaultConfiguration": {"level": "error"}}],
                          results=[{"ruleIndex": 0}]),
            expected_counts={"error": 1, "warning": 0},
        ), 1)

    def test_rule_reference_resolves_inherited_error(self):
        self.assertEqual(self.execute(
            output=report(rules=[{"id": "critical-rule", "defaultConfiguration": {"level": "error"}}],
                          results=[{"rule": {"id": "critical-rule", "index": 0}}]),
            expected_counts={"error": 1},
        ), 1)

    def test_missing_rule_default_is_warning(self):
        self.assertEqual(self.execute(
            output=report(rules=[{"id": "unconfigured"}], results=[{"ruleId": "unconfigured"}]),
            expected_counts={"error": 0, "warning": 1},
        ), 0)

    def test_unknown_rule_uses_warning_default(self):
        self.assertEqual(self.execute(
            output=report(results=[{"ruleId": "unknown"}]),
            expected_counts={"error": 0, "warning": 1},
        ), 0)

    def test_non_failure_kind_defaults_to_none(self):
        self.assertEqual(self.execute(
            output=report(rules=[{"id": "critical-rule", "defaultConfiguration": {"level": "error"}}],
                          results=[{"ruleId": "critical-rule", "kind": "pass"}]),
            expected_counts={"error": 0, "other": 1},
        ), 0)

    def test_suppression_metadata_does_not_relax_existing_error_policy(self):
        self.assertEqual(self.execute(
            output=report(rules=[{"id": "critical-rule", "defaultConfiguration": {"level": "error"}}],
                          results=[{"ruleId": "critical-rule", "suppressions": [{"kind": "inSource"}]}]),
            expected_counts={"error": 1},
        ), 1)

    def test_rules_are_resolved_within_each_run(self):
        first = json.loads(report(rules=[{"id": "same-id", "defaultConfiguration": {"level": "error"}}],
                                  results=[{"ruleId": "same-id"}]))
        second = json.loads(report(rules=[{"id": "same-id", "defaultConfiguration": {"level": "note"}}],
                                   results=[{"ruleId": "same-id"}]))
        first["runs"].extend(second["runs"])
        self.assertEqual(self.execute(output=json.dumps(first), expected_counts={"error": 1, "note": 1}), 1)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *unittest_arguments])
