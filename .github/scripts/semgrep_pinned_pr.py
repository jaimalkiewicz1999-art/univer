"""Run pinned local Semgrep rules; publish only allowlisted execution evidence.

Raw SARIF, scanner output and shared-gate diagnostics remain in runner temporary
storage. No rule source is executed, vendored or included in uploaded artifacts.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import traceback

from semgrep_sarif import report_counts


VERSION = "1.186.0"
RULES_COMMIT = "a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2"
MANIFEST = Path(__file__).resolve().parents[1] / "semgrep/pinned-rules.json"
GATE = Path(__file__).with_name("semgrep_sarif.py")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def git_head(path):
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], stderr=subprocess.PIPE, timeout=10,
    ).decode("ascii").strip()


def reconstruct_rules(source, manifest, destination):
    import yaml

    if yaml.__version__ != "6.0.3" or manifest["commit"] != RULES_COMMIT:
        raise ValueError("Unexpected serializer or rule revision")
    if git_head(source) != RULES_COMMIT:
        raise ValueError("Unexpected rule checkout")
    source = source.resolve()
    selected, cache = [], {}
    for item in manifest["provenance"]:
        relative = PurePosixPath(item["path"])
        path = (source / relative).resolve()
        if relative.is_absolute() or ".." in relative.parts or not path.is_relative_to(source):
            raise ValueError("Rule path escapes its checkout")
        if path not in cache:
            cache[path] = yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]
        matches = [rule for rule in cache[path] if rule["id"] == item["original_id"]]
        if len(matches) != 1:
            raise ValueError("Rule identity is ambiguous or missing")
        rule = dict(matches[0])
        rule["id"] = item["id"]
        selected.append(rule)
    if len(selected) != manifest["rule_count"] or len({rule["id"] for rule in selected}) != len(selected):
        raise ValueError("Unexpected rule count or duplicate identity")
    rendered = yaml.safe_dump({"rules": selected}, sort_keys=False).encode("utf-8")
    if hashlib.sha256(rendered).hexdigest() != manifest["config_sha256"]:
        raise ValueError("Reconstructed configuration differs from reviewed bytes")
    if digest(source / "LICENSE") != manifest["license_sha256"]:
        raise ValueError("Upstream license notice differs")
    destination.mkdir(parents=True, exist_ok=True)
    config = destination / "rules.yaml"
    config.write_bytes(rendered)
    shutil.copyfile(source / "LICENSE", destination / "LICENSE")
    (destination / "MODIFICATIONS.txt").write_text(
        "Private CI copy selected from semgrep/semgrep-rules at " + RULES_COMMIT + ".\n"
        "MODIFIED: selected rules only; rule IDs are namespaced using pinned-rules.json.\n"
        "Rule definitions and embedded notices are otherwise retained. No redistribution.\n",
        encoding="utf-8",
    )
    return config


def capture(command, log, *, environment=None, timeout=720):
    with log.open("wb") as stream:
        process = subprocess.Popen(
            command, stdout=stream, stderr=subprocess.STDOUT,
            env=environment, start_new_session=True,
        )
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return 124


def scan_command(config, report):
    return [
        "semgrep", "scan", "--config", str(config), "--metrics", "off",
        "--disable-version-check", "--jobs", "2", "--sarif", "--output", str(report), ".",
    ]


def numeric_statistics(log):
    text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    patterns = {
        "rules_run": r"Rules run:\s*(\d+)",
        "targets_scanned": r"Targets scanned:\s*(\d+)",
        "active_findings": r"Findings:\s*(\d+)",
        "parsed_lines_percent": r"Parsed lines:\s*~?(\d+(?:\.\d+)?)%",
        "oversize_files_skipped": r"Files larger than[^\r\n]*?:\s*(\d+)",
    }
    values = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        values[key] = (float(match[1]) if key == "parsed_lines_percent" else int(match[1])) if match else None
    return values


def validated_counts(sarif):
    if not isinstance(sarif, dict) or sarif.get("version") != "2.1.0":
        raise ValueError("Invalid SARIF version")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("Missing SARIF runs")
    notifications = {"total": 0, "error": 0, "warning": 0, "note": 0, "other": 0}
    for run in runs:
        driver = run["tool"]["driver"]
        if driver.get("semanticVersion") != VERSION or not isinstance(run.get("results"), list):
            raise ValueError("Unexpected tool version or result structure")
        invocations = run.get("invocations")
        if not isinstance(invocations, list) or not invocations:
            raise ValueError("Missing scanner invocation evidence")
        if any(type(invocation.get("executionSuccessful")) is not bool for invocation in invocations):
            raise ValueError("Missing scanner execution status")
        for invocation in invocations:
            diagnostics = invocation.get("toolExecutionNotifications", [])
            if not isinstance(diagnostics, list) or any(not isinstance(item, dict) for item in diagnostics):
                raise ValueError("Invalid scanner diagnostic structure")
            for diagnostic in diagnostics:
                level = diagnostic.get("level", "warning")
                key = level if level in ("error", "warning", "note") else "other"
                notifications["total"] += 1
                notifications[key] += 1
    counts, failed = report_counts(sarif)
    return counts, not failed, notifications


def evaluate_report(report, scanner_log, scanner_exit, private):
    evidence = {
        "scanner_exit_code": scanner_exit, "gate_exit_code": 2,
        "shared_gate_exit_code": None, "execution_successful": None,
        "report_valid": False, "report_sha256": None, "counts": None,
        "tool_execution_notifications": None,
        "statistics": numeric_statistics(scanner_log), "status": "invalid_report",
    }
    try:
        if not report.is_file() or report.stat().st_size == 0:
            raise ValueError("Missing or empty report")
        evidence["report_sha256"] = digest(report)
        counts, successful, notifications = validated_counts(json.loads(report.read_text(encoding="utf-8")))
        evidence.update(report_valid=True, counts=counts, execution_successful=successful,
                        tool_execution_notifications=notifications)
    except Exception:
        (private / "report-validation.log").write_text(traceback.format_exc(), encoding="utf-8")
    if scanner_exit != 0:
        evidence.update(status="scanner_failed", gate_exit_code=scanner_exit if scanner_exit > 0 else 2)
    elif evidence["report_valid"]:
        code = capture(
            [sys.executable, str(GATE), "gate", "--report", str(report)],
            private / "shared-gate.log", timeout=30,
        )
        evidence.update(shared_gate_exit_code=code, gate_exit_code=code if code >= 0 else 2)
        evidence["status"] = "passed" if code == 0 else "gate_failed"
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-source", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    args.private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    private = Path(tempfile.mkdtemp(prefix="run-", dir=args.private_root))
    evidence = {
        "schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(),
        "source_sha": None, "semgrep_version": None, "semgrep_core_sha256": None,
        "semgrep_distribution_record_sha256": None, "python_version": platform.python_version(),
        "rules_commit": RULES_COMMIT, "rules_selected": None, "config_sha256": None,
        "metrics": "off", "version_check": False, "registry_config": False,
        "gate_exit_code": 2, "status": "preflight_failed",
    }
    try:
        expected = os.environ.get("EXPECTED_SOURCE_SHA", "")
        if not re.fullmatch(r"[0-9a-f]{40}", expected) or git_head(Path.cwd()) != expected:
            raise ValueError("Source identity mismatch")
        evidence["source_sha"] = expected
        if any(os.environ.get(name) != "success" for name in (
            "PYTHON_OUTCOME", "INSTALL_OUTCOME", "TESTS_OUTCOME", "RULES_OUTCOME",
        )):
            raise ValueError("An earlier required step did not succeed")
        distribution = importlib.metadata.distribution("semgrep")
        if distribution.version != VERSION:
            raise ValueError("Unexpected scanner version")
        core = [distribution.locate_file(file) for file in distribution.files if str(file) == "semgrep/bin/semgrep-core"]
        if len(core) != 1:
            raise ValueError("Scanner engine is missing")
        evidence.update(
            semgrep_version=distribution.version, semgrep_core_sha256=digest(Path(core[0])),
            semgrep_distribution_record_sha256=hashlib.sha256(distribution.read_text("RECORD").encode()).hexdigest(),
        )
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        config = reconstruct_rules(args.rules_source, manifest, private / "rules")
        evidence.update(rules_selected=manifest["rule_count"], config_sha256=digest(config))
        environment = os.environ.copy()
        environment.pop("SEMGREP_APP_TOKEN", None)
        environment.update(
            SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0",
            SEMGREP_SETTINGS_FILE=str(private / "settings.yaml"),
        )
        report, scanner_log = private / "scan.sarif", private / "scanner.log"
        code = capture(scan_command(config, report), scanner_log, environment=environment)
        evidence.update(evaluate_report(report, scanner_log, code, private))
    except Exception:
        (private / "preflight-or-wrapper-error.log").write_text(traceback.format_exc(), encoding="utf-8")
    evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(evidence, indent=2) + "\n"
    args.evidence.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return evidence["gate_exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
