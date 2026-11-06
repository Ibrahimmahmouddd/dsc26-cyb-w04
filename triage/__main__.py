"""Command line: python -m triage --sarif S --bandit B --project NAME [options]"""
import argparse
import json
import sys
from datetime import date

from triage.core import (
    apply_suppressions, dedupe, diff_baseline, gate, load_bandit,
    load_semgrep_sarif, load_suppressions,
)


def _group_json(g):
    return {
        "key": g.key,
        "path": g.path,
        "line": g.line,
        "severity": g.severity,
        "tools": g.tools,
        "fingerprints": g.fingerprints,
    }


def _load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="triage")
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--bandit", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--equivalences")
    ap.add_argument("--baseline")
    ap.add_argument("--suppressions")
    ap.add_argument("--today")
    ap.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical"])
    args = ap.parse_args(argv)

    try:
        findings = load_semgrep_sarif(args.sarif, args.project)
        findings += load_bandit(args.bandit, args.project)
        equivalences = _load_json(args.equivalences) if args.equivalences else {}
        baseline = set(_load_json(args.baseline)) if args.baseline else set()
        entries = _load_json(args.suppressions) if args.suppressions else []
        today = date.fromisoformat(args.today) if args.today else date.today()
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    groups = dedupe(findings, equivalences)
    suppressions, invalid = load_suppressions(entries)
    active, suppressed = apply_suppressions(groups, suppressions, today)
    new, existing, fixed = diff_baseline(active, baseline)
    passed = gate(new, args.fail_on)

    print(json.dumps({
        "passed": passed,
        "new": [_group_json(g) for g in new],
        "existing": [_group_json(g) for g in existing],
        "suppressed": [_group_json(g) for g in suppressed],
        "fixed": fixed,
        "invalid_suppressions": len(invalid),
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())