# Diwan SAST triage (dsc26-cyb-w04)

### Commands
- Tests: `python -m pytest -q` from the repo root (plain `pytest` breaks imports)
- CLI: `python -m triage --sarif fixtures/semgrep.sarif --bandit fixtures/bandit.json --project diwan_invoicing --equivalences fixtures/equivalences.json --baseline fixtures/baseline.json --suppressions fixtures/suppressions.json --today 2026-11-05`

### Rules that differ from defaults
- Standard library only. Never add packages.
- Never edit `fixtures/`: the grader replaces it with its own copy.
- Keep names and signatures in `triage/core.py`: the grader imports them.
- Load JSON/YAML only with safe loaders (`json.load`, `yaml.safe_load`). Never `yaml.load`.
- Fingerprint = sha256 of `tool|rule_id|path|code`, code whitespace collapsed. Never include the line number.
- A suppression expiring today still applies (`expires >= today`).
- Order: dedupe, then suppressions, then baseline, then gate on new only.
- Never lose a finding: group sizes must add up to the input count.
- Output must not depend on input order (sort members and groups).

### Known traps
- Bandit `code` lines start with their line number: match the exact number (9 vs 10 vs 100).
- `security-severity` of 0, "abc" or above 10 is ignored; use the level instead.
- Project name appears twice in CI paths: cut after its LAST occurrence.

### Security
- Never read or print `.env`, keys or real logs.
- Never run a scanner on anything we do not own.
- Threat model lives in dsc26-cyb-w02 (models/rawaj_scoring.yaml).

### Before saying done
- `python -m pytest -q` passes and new behaviour has a test.
- `AI_USAGE.md` keeps its three headings.