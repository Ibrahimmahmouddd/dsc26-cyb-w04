"""triage: read Semgrep SARIF and Bandit JSON, dedupe, suppress, diff a baseline, gate a build."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date

SEVERITIES = ["info", "low", "medium", "high", "critical"]   # lowest to highest


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    path: str
    line: int
    severity: str
    cwe: int | None
    message: str
    code: str


@dataclass
class Group:
    key: str
    path: str
    line: int
    severity: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({f.tool for f in self.findings})

    @property
    def fingerprints(self) -> list[str]:
        return sorted(fingerprint(f) for f in self.findings)


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


def normalize_path(raw: str, project: str) -> str:
    p = raw.replace("\\", "/")
    if p.startswith("file://"):
        p = p[len("file://"):]
    parts = [s for s in p.split("/") if s not in ("", ".")]
    if project in parts:
        last = len(parts) - 1 - parts[::-1].index(project)
        parts = parts[last + 1:]
    return "/".join(parts)


def fingerprint(f: Finding) -> str:
    code = " ".join(f.code.split())
    text = f"{f.tool}|{f.rule_id}|{f.path}|{code}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _score_severity(value):
    """Map a security-severity value, or None if it is not a number in (0, 10]."""
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 < score <= 10:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _read_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    data = _read_json(path)
    findings: list[Finding] = []
    for run in data.get("runs", []) or []:
        rules = {}
        driver = ((run.get("tool") or {}).get("driver")) or {}
        for rule in driver.get("rules", []) or []:
            rules[rule.get("id")] = rule
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId")
            rule = rules.get(rule_id, {})
            props = rule.get("properties") or {}

            severity = _score_severity(props.get("security-severity"))
            if severity is None:
                level = res.get("level")
                if level is None:
                    level = (rule.get("defaultConfiguration") or {}).get("level")
                if level is None:
                    level = "warning"
                severity = _LEVELS.get(level, "medium")

            cwe = None
            for tag in props.get("tags", []) or []:
                m = re.match(r"CWE-(\d+)", str(tag))
                if m:
                    cwe = int(m.group(1))
                    break

            loc = (res.get("locations") or [{}])[0].get("physicalLocation") or {}
            uri = (loc.get("artifactLocation") or {}).get("uri", "")
            region = loc.get("region") or {}
            snippet = (region.get("snippet") or {}).get("text", "") or ""
            code = snippet.splitlines()[0] if snippet else ""

            findings.append(Finding(
                tool="semgrep",
                rule_id=rule_id,
                path=normalize_path(uri, project),
                line=region.get("startLine", 0),
                severity=severity,
                cwe=cwe,
                message=(res.get("message") or {}).get("text", ""),
                code=code,
            ))
    return findings


_BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_DOWN = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}


def _bandit_code_line(block: str, line_number: int) -> str:
    for row in (block or "").splitlines():
        num, _, text = row.partition(" ")
        if num.isdigit() and int(num) == line_number:
            return text
    return ""


def load_bandit(path, project: str) -> list[Finding]:
    data = _read_json(path)
    findings: list[Finding] = []
    for r in data.get("results", []) or []:
        severity = _BANDIT_SEV.get(r.get("issue_severity"), "info")
        if r.get("issue_confidence") == "LOW":
            severity = _DOWN[severity]
        cwe_obj = r.get("issue_cwe") or {}
        cwe = cwe_obj.get("id")
        line = r.get("line_number", 0)
        findings.append(Finding(
            tool="bandit",
            rule_id=r.get("test_id"),
            path=normalize_path(r.get("filename", ""), project),
            line=line,
            severity=severity,
            cwe=cwe,
            message=r.get("issue_text", ""),
            code=_bandit_code_line(r.get("code", ""), line),
        ))
    return findings


def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    own = f"{f.tool}:{f.rule_id}"
    if own in equivalences:
        return equivalences[own]
    if f.cwe is not None:
        return f"CWE-{f.cwe}"
    return own


def _sev_rank(s: str) -> int:
    return SEVERITIES.index(s)


def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]:
    equivalences = equivalences or {}
    buckets: dict[tuple, list[Finding]] = {}
    for f in findings:
        buckets.setdefault((f.path, f.line, issue_key(f, equivalences)), []).append(f)
    groups = []
    for (path, line, key), members in buckets.items():
        members = sorted(members, key=lambda m: (m.tool, m.rule_id, fingerprint(m)))
        top = max((m.severity for m in members), key=_sev_rank)
        groups.append(Group(key=key, path=path, line=line, severity=top, findings=members))
    groups.sort(key=lambda g: (-_sev_rank(g.severity), g.path, g.line, g.key))
    return groups


_HEX64 = re.compile(r"[0-9a-f]{64}")


def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    valid, invalid = [], []
    for e in entries:
        try:
            fp = e.get("fingerprint")
            reason = e.get("reason")
            by = e.get("by")
            exp = e.get("expires")
            if not (isinstance(fp, str) and _HEX64.fullmatch(fp)):
                raise ValueError("fingerprint")
            if not (isinstance(reason, str) and len(reason.strip()) >= 10):
                raise ValueError("reason")
            if not (isinstance(by, str) and by.strip()):
                raise ValueError("by")
            if not isinstance(exp, str):
                raise ValueError("expires")
            valid.append(Suppression(fp, reason, date.fromisoformat(exp), by))
        except (ValueError, TypeError, AttributeError):
            invalid.append(e)
    return valid, invalid


def apply_suppressions(groups: list[Group], suppressions: list[Suppression],
                       today: date) -> tuple[list[Group], list[Group]]:
    live = {s.fingerprint for s in suppressions if s.expires >= today}
    active, suppressed = [], []
    for g in groups:
        if any(fp in live for fp in g.fingerprints):
            suppressed.append(g)
        else:
            active.append(g)
    return active, suppressed


def diff_baseline(groups: list[Group], baseline: set[str]) -> tuple[list[Group], list[Group], list[str]]:
    new, existing, seen = [], [], set()
    for g in groups:
        fps = g.fingerprints
        seen.update(fps)
        if any(fp in baseline for fp in fps):
            existing.append(g)
        else:
            new.append(g)
    fixed = sorted(set(baseline) - seen)
    return new, existing, fixed


def gate(new_active: list[Group], fail_on: str) -> bool:
    """True means the build passes."""
    limit = SEVERITIES.index(fail_on)
    return not any(_sev_rank(g.severity) >= limit for g in new_active)