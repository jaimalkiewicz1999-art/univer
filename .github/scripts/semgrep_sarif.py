"""Shared severity resolution for Semgrep SARIF summaries and the CI gate.

SARIF 2.1.0 sections 3.27.10 and 3.50.3: an omitted result level inherits
the rule's defaultConfiguration.level, which itself defaults to warning.
This resolves Semgrep's driver rules by ruleId or ruleIndex.
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import argparse
import json
import os
from pathlib import Path


def effective_level(run, result):
    """Resolve an explicit level or the referenced driver's rule default."""
    if "level" in result:
        level = result["level"]
    elif result.get("kind", "fail") != "fail":
        level = "none"
    else:
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        reference = result.get("rule", {})
        rule_id = result.get("ruleId", reference.get("id"))
        rule_index = result.get("ruleIndex", reference.get("index"))
        descriptor = (
            next((rule for rule in rules if rule.get("id") == rule_id), None)
            if rule_id is not None else None
        )
        if descriptor is None and type(rule_index) is int and 0 <= rule_index < len(rules):
            descriptor = rules[rule_index]
        level = (descriptor or {}).get("defaultConfiguration", {}).get("level", "warning")
    if level not in ("error", "warning", "note", "none"):
        raise ValueError("Invalid SARIF severity")
    return level


def report_counts(sarif):
    counts = {"error": 0, "warning": 0, "note": 0, "other": 0}
    failed_invocations = False
    for run in sarif.get("runs", []):
        failed_invocations = failed_invocations or any(
            invocation.get("executionSuccessful") is False
            for invocation in run.get("invocations", [])
        )
        for result in run.get("results", []):
            level = effective_level(run, result)
            counts[level if level in counts else "other"] += 1
    return counts, failed_invocations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("summary", "gate"))
    parser.add_argument("--report", type=Path, default=Path("reports/semgrep.sarif"))
    parser.add_argument("--artifact", default="semgrep-sarif")
    args = parser.parse_args()
    with args.report.open(encoding="utf-8") as file:
        counts, failed_invocations = report_counts(json.load(file))
    if args.mode == "summary":
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write("## Semgrep report\n")
            summary.write(f"- Total findings: {sum(counts.values())}\n")
            for level in ("error", "warning", "note", "other"):
                summary.write(f"- {level.title()}: {counts[level]}\n")
            summary.write(f"- Exit code: {os.environ['SEMGREP_EXIT_CODE']}\n")
            summary.write(f"- Semgrep install: {os.environ['INSTALL_OUTCOME']}\n")
            summary.write(f"- Artifact: `{args.artifact}`\n")
            summary.write(f"- Code scanning upload: {os.environ.get('SARIF_UPLOAD_OUTCOME') or 'skipped'}\n")
        return 0
    if failed_invocations:
        print("Semgrep reported an unsuccessful scanner invocation.")
        return 2
    if counts["error"]:
        print(f"Semgrep reported {counts['error']} error-level finding(s).")
        print("See the uploaded SARIF artifact for details.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
