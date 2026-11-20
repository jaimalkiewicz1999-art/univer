"""Offline wrapper/privacy regressions; these do not establish a hosted scan."""

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ruamel.yaml import YAML
import yaml

import semgrep_pinned_pr as wrapper


PRIVATE = "PRIVATE_FINDING_DO_NOT_PUBLISH"
# This exact application-only workflow was reviewed independently. Any change
# requires a new review; its same-repository guard is not a general exception.
REVIEWED_APPLICATION_WORKFLOW_SHA256 = "dae134f086290e1318c1ee918d2462c9631c4399883d2a8a1c62a91786f22646"
# Separate exact-byte exception for the fixed-base application coverage recovery.
REVIEWED_BASELINE_RECOVERY_WORKFLOW_SHA256 = "5a134ca2262cbbcedf06d1043d53512b8863849d5d100aa51cebf87e7dea45ff"
LOG = (
    PRIVATE + " /private/source.js unsafe example\n"
    "Rules run: 191\nTargets scanned: 7233\nFindings: 154\n"
    "Parsed lines: ~99.9%\nFiles larger than files 1.0 MB: 7\n"
)


def report(level=None, successful=True, inherited=False):
    driver = {"name": "Semgrep OSS", "semanticVersion": wrapper.VERSION}
    result = {
        "message": {"text": PRIVATE}, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": PRIVATE}, "region": {"snippet": {"text": PRIVATE}},
        }}],
    }
    if inherited:
        driver["rules"] = [{"id": "fixture-rule", "defaultConfiguration": {"level": level}}]
        result["ruleId"] = "fixture-rule"
    elif level is not None:
        result["level"] = level
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": driver}, "invocations": [{"executionSuccessful": successful}],
        "results": [] if level is None else [result],
    }]}


class ReportTests(unittest.TestCase):
    def evaluate(self, data, scanner_exit=0):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            sarif, log = private / "raw.sarif", private / "raw.log"
            if data is not None:
                sarif.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
            log.write_text(LOG, encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                evidence = wrapper.evaluate_report(sarif, log, scanner_exit, private)
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn(PRIVATE, json.dumps(evidence))
            self.assertNotIn("/private/source.js", json.dumps(evidence))
            self.assertEqual(evidence["statistics"]["targets_scanned"], 7233)
            return evidence

    def test_error_findings_and_inherited_errors_use_unchanged_gate(self):
        for inherited in (False, True):
            with self.subTest(inherited=inherited):
                evidence = self.evaluate(report("error", inherited=inherited))
                self.assertEqual(evidence["gate_exit_code"], 1)
                self.assertEqual(evidence["shared_gate_exit_code"], 1)
                self.assertEqual(evidence["counts"]["error"], 1)

    def test_warning_and_zero_findings_preserve_policy(self):
        for data in (report("warning"), report()):
            with self.subTest(data=data):
                self.assertEqual(self.evaluate(data)["gate_exit_code"], 0)

    def test_missing_empty_malformed_and_structurally_invalid_reports_fail(self):
        for data in (None, "", "invalid JSON " + PRIVATE, {}, [],
                     {"version": "2.1.0", "runs": []}, {"version": "2.1.0", "runs": [{}]}):
            with self.subTest(data=data):
                self.assertEqual(self.evaluate(data)["gate_exit_code"], 2)

    def test_missing_or_failed_invocations_fail(self):
        for invocation in (None, [], [{}], [{"executionSuccessful": False}]):
            data = report()
            data["runs"][0]["invocations"] = invocation
            with self.subTest(invocation=invocation):
                self.assertEqual(self.evaluate(data)["gate_exit_code"], 2)

    def test_scanner_nonzero_exit_is_preserved_without_raw_output(self):
        evidence = self.evaluate(report("error"), scanner_exit=7)
        self.assertEqual(evidence["gate_exit_code"], 7)
        self.assertIsNone(evidence["shared_gate_exit_code"])

    def test_diagnostic_counts_exclude_notification_ids_messages_and_paths(self):
        data = report("error")
        data["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [
            {"level": level, "descriptor": {"id": PRIVATE}, "message": {"text": PRIVATE},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": PRIVATE}}}]}
            for level in ("warning", "error")
        ]
        evidence = self.evaluate(data)
        self.assertEqual(evidence["gate_exit_code"], 1)
        self.assertEqual(evidence["tool_execution_notifications"], {
            "total": 2, "error": 1, "warning": 1, "note": 0, "other": 0,
        })
        self.assertNotIn("descriptor", json.dumps(evidence))
        self.assertNotIn("locations", json.dumps(evidence))
        self.assertNotIn("message", json.dumps(evidence))

    def test_unknown_severity_and_wrong_tool_version_fail(self):
        data = report("invalid")
        self.assertEqual(self.evaluate(data)["gate_exit_code"], 2)
        data = report()
        data["runs"][0]["tool"]["driver"]["semanticVersion"] = "0.0.0"
        self.assertEqual(self.evaluate(data)["gate_exit_code"], 2)

    def test_command_uses_only_local_config_with_metrics_and_version_checks_off(self):
        command = wrapper.scan_command(Path("local-rules.yaml"), Path("private/scan.sarif"))
        self.assertEqual(command[command.index("--config") + 1], "local-rules.yaml")
        self.assertEqual(command[command.index("--metrics") + 1], "off")
        self.assertIn("--disable-version-check", command)
        self.assertNotIn("auto", command)
        self.assertEqual(command[-1], ".")

    def test_capture_keeps_nonzero_output_private_and_bounds_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "raw.log"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = wrapper.capture([sys.executable, "-c", f"print({PRIVATE!r}); raise SystemExit(7)"], log)
            self.assertEqual(code, 7)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn(PRIVATE, log.read_text())
            self.assertEqual(wrapper.capture([sys.executable, "-c", "import time; time.sleep(5)"], log, timeout=0.05), 124)

    def test_preflight_exception_produces_only_sanitized_artifact_and_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "public/execution.json"
            argv = ["wrapper", "--rules-source", str(root / "rules"), "--private-root", str(root / "private"), "--evidence", str(output)]
            env = {name: "success" for name in ("PYTHON_OUTCOME", "INSTALL_OUTCOME", "TESTS_OUTCOME", "RULES_OUTCOME")}
            env["EXPECTED_SOURCE_SHA"] = "a" * 40
            stdout = io.StringIO()
            with patch.object(sys, "argv", argv), patch.dict(os.environ, env), \
                 patch.object(wrapper, "git_head", return_value="a" * 40), \
                 patch.object(wrapper.importlib.metadata, "distribution", side_effect=RuntimeError(PRIVATE)), \
                 redirect_stdout(stdout):
                self.assertEqual(wrapper.main(), 2)
            self.assertNotIn(PRIVATE, stdout.getvalue())
            self.assertNotIn(PRIVATE, output.read_text())
            self.assertEqual(list(output.parent.iterdir()), [output])


class ReconstructionTests(unittest.TestCase):
    def test_exact_reconstruction_and_mismatch_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            rule = {"id": "fixture", "message": "fixture", "languages": ["javascript"], "severity": "WARNING", "pattern": "fixture(...)"}
            (source / "rule.yaml").write_text(yaml.safe_dump({"rules": [rule]}, sort_keys=False))
            (source / "LICENSE").write_text("Fixture license notice\n")
            expected = dict(rule, id="local.fixture")
            rendered = yaml.safe_dump({"rules": [expected]}, sort_keys=False).encode()
            manifest = {
                "commit": wrapper.RULES_COMMIT, "rule_count": 1,
                "config_sha256": hashlib.sha256(rendered).hexdigest(),
                "license_sha256": wrapper.digest(source / "LICENSE"),
                "provenance": [{"path": "rule.yaml", "original_id": "fixture", "id": "local.fixture"}],
            }
            with patch.object(wrapper, "git_head", return_value=wrapper.RULES_COMMIT):
                config = wrapper.reconstruct_rules(source, manifest, root / "out")
                self.assertEqual(config.read_bytes(), rendered)
                self.assertEqual((config.parent / "LICENSE").read_bytes(), (source / "LICENSE").read_bytes())
                manifest["config_sha256"] = "0" * 64
                with self.assertRaises(ValueError):
                    wrapper.reconstruct_rules(source, manifest, root / "bad")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parents[1] / "workflows"
        self.yaml = YAML(typ="safe")
        self.workflow = self.yaml.load((self.directory / "security-semgrep-pinned-pr.yml").read_text())

    def test_supplemental_trigger_permissions_and_artifact_scope(self):
        self.assertEqual(self.workflow["on"], {"pull_request": {"branches": ["dev"], "types": ["opened", "synchronize", "reopened"]}})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        job = self.workflow["jobs"]["pinned-scan"]
        self.assertEqual(job["if"], "github.repository == 'jaimalkiewicz1999-art/univer' && github.event.pull_request.head.repo.full_name == github.repository")
        self.assertNotIn("permissions", job)
        self.assertEqual(job["steps"][0]["with"]["ref"], "${{ github.event.pull_request.head.sha }}")
        self.assertFalse(job["steps"][0]["with"]["persist-credentials"])
        uploads = [step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["with"]["path"], "${{ runner.temp }}/semgrep-pinned-evidence/execution.json")
        self.assertEqual(uploads[0]["if"], "${{ always() }}")
        for step in job["steps"]:
            self.assertNotIn("continue-on-error", step)
            if "uses" in step:
                self.assertRegex(step["uses"], r"^[a-z-]+/[a-z-]+@[0-9a-f]{40}$")
        self.assertNotIn("secrets.", json.dumps(self.workflow))
        self.assertNotIn("security-events", json.dumps(self.workflow))

    def assert_workflow_admission(self):
        auto = self.yaml.load((self.directory / "security-semgrep.yml").read_text())
        self.assertEqual(set(auto["on"]), {"push", "workflow_dispatch"})
        self.assertEqual(auto["on"]["push"]["branches"], ["main", "dev"])
        allowed_conditions = {
            "github.repository == 'dream-num/univer' && (github.event_name != 'pull_request' || !github.event.pull_request.draft)",
            "always() && github.repository == 'dream-num/univer' && (github.event_name != 'pull_request' || !github.event.pull_request.draft)",
            "github.repository == 'dream-num/univer' && !github.event.pull_request.draft",
        }
        for path in self.directory.glob("*.yml"):
            if path.name == "security-semgrep-pinned-pr.yml":
                continue
            if path.name == "clipboard-pr-acceptance.yml":
                self.assertEqual(wrapper.digest(path), REVIEWED_APPLICATION_WORKFLOW_SHA256,
                                 "Application workflow changed; review its complete execution scope")
                continue
            if path.name == "baseline-coverage-recovery.yml":
                self.assertEqual(wrapper.digest(path), REVIEWED_BASELINE_RECOVERY_WORKFLOW_SHA256,
                                 "Baseline recovery changed; review its complete execution scope")
                continue
            workflow = self.yaml.load(path.read_text())
            self.assertNotIn("workflow_run", workflow["on"])
            self.assertNotIn("pull_request_target", workflow["on"])
            if "pull_request" in workflow["on"]:
                for job in workflow["jobs"].values():
                    self.assertIn(job["if"], allowed_conditions, path.name)

    def test_existing_workflows_cannot_invoke_auto_scan_on_this_pr_update(self):
        self.assert_workflow_admission()

    def test_unreviewed_application_workflow_mutations_are_rejected(self):
        original = (self.directory / "clipboard-pr-acceptance.yml").read_text()
        auto = (self.directory / "security-semgrep.yml").read_text()
        mutations = [
            original.replace("pull_request:", "pull_request_target:", 1),
            original.replace("contents: read", "contents: write", 1),
            original.replace("jaimalkiewicz1999-art/univer", "unreviewed-owner/univer", 1),
            original.replace("pnpm --filter @univerjs/ui typecheck", "semgrep --config auto .", 1),
            original.replace("persist-credentials: false", "persist-credentials: true", 1),
        ]
        for mutated in mutations:
            self.assertNotEqual(mutated, original)
            with self.subTest(workflow=hashlib.sha256(mutated.encode()).hexdigest()), \
                 tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "security-semgrep.yml").write_text(auto)
                (root / "clipboard-pr-acceptance.yml").write_text(mutated)
                with patch.object(self, "directory", root), self.assertRaises(AssertionError):
                    self.assert_workflow_admission()

    def test_application_workflow_exception_does_not_admit_another_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security-semgrep.yml").write_bytes((self.directory / "security-semgrep.yml").read_bytes())
            (root / "unreviewed-application.yml").write_bytes((self.directory / "clipboard-pr-acceptance.yml").read_bytes())
            with patch.object(self, "directory", root), self.assertRaises(AssertionError):
                self.assert_workflow_admission()

    def test_baseline_recovery_is_read_only_and_bound_to_the_reviewed_base(self):
        workflow = self.yaml.load((self.directory / "baseline-coverage-recovery.yml").read_text())
        self.assertEqual(set(workflow["on"]), {"pull_request"})
        self.assertEqual(workflow["on"]["pull_request"]["branches"], ["dev"])
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(workflow["jobs"]), {"baseline"})
        job = workflow["jobs"]["baseline"]
        self.assertEqual(job["if"], "github.repository == 'jaimalkiewicz1999-art/univer' && github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.number == 1")
        self.assertEqual(job["timeout-minutes"], 25)
        self.assertEqual(job["strategy"]["matrix"], {"project": ["engine-render", "sheets-ui"]})
        self.assertNotIn("permissions", job)
        checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@"))
        self.assertEqual(checkout["with"]["ref"], "618f9df2cb09e0dbe669b0dd0de5a9fbd5e6bb7f")
        self.assertFalse(checkout["with"]["persist-credentials"])
        setup = next(s for s in job["steps"] if s.get("uses", "").startswith("pnpm/setup@"))
        self.assertFalse(setup["with"]["cache"])
        upload = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertEqual(upload["with"]["path"].splitlines(), [
            "${{ env.EVIDENCE_DIR }}/" + name for name in ["provenance.json", "source-inventory.json",
            "test-results.json", "coverage-final.json", "coverage-summary.json", "test-stdout.log"]])
        for step in job["steps"]:
            self.assertNotIn("continue-on-error", step)
            if "uses" in step:
                self.assertRegex(step["uses"], r"^[a-z-]+/[a-z-]+@[0-9a-f]{40}$")
        self.assertNotIn("secrets.", json.dumps(workflow))

    def test_unreviewed_baseline_recovery_mutations_are_rejected(self):
        original = (self.directory / "baseline-coverage-recovery.yml").read_text()
        auto = (self.directory / "security-semgrep.yml").read_text()
        mutations = [
            original.replace("pull_request:", "pull_request_target:", 1),
            original.replace("contents: read", "contents: write", 1),
            original.replace("jaimalkiewicz1999-art/univer", "unreviewed-owner/univer", 1),
            original.replace("ref: 618f9df2cb09e0dbe669b0dd0de5a9fbd5e6bb7f", "ref: ${{ github.event.pull_request.head.sha }}", 1),
            original.replace("persist-credentials: false", "persist-credentials: true", 1),
            original.replace('"coverage", "--maxWorkers=1"', '"coverage", "src/one.spec.ts", "--maxWorkers=1"', 1),
            original.replace("--max-old-space-size=1024", "--max-old-space-size=1536", 1),
            original.replace("${{ env.EVIDENCE_DIR }}/test-stdout.log", "${{ env.SOURCE_ROOT }}/**", 1),
        ]
        for mutated in mutations:
            self.assertNotEqual(mutated, original)
            with self.subTest(workflow=hashlib.sha256(mutated.encode()).hexdigest()), \
                 tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "security-semgrep.yml").write_text(auto)
                (root / "baseline-coverage-recovery.yml").write_text(mutated)
                with patch.object(self, "directory", root), self.assertRaises(AssertionError):
                    self.assert_workflow_admission()

    def test_baseline_recovery_exception_does_not_admit_another_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security-semgrep.yml").write_bytes((self.directory / "security-semgrep.yml").read_bytes())
            (root / "unreviewed-recovery.yml").write_bytes((self.directory / "baseline-coverage-recovery.yml").read_bytes())
            with patch.object(self, "directory", root), self.assertRaises(AssertionError):
                self.assert_workflow_admission()

    def test_manifest_pins_the_reviewed_source_and_bytes(self):
        manifest = json.loads(wrapper.MANIFEST.read_text())
        self.assertEqual(manifest["commit"], wrapper.RULES_COMMIT)
        self.assertEqual(manifest["rule_count"], 196)
        self.assertEqual(manifest["config_sha256"], "da388503c6694eb209146d3ac991a6ae967ed00d99e4d5b3d44670f3cafb9b2a")


if __name__ == "__main__":
    unittest.main()
