#!/usr/bin/env python3
"""
Convert scanner output into a single GitLab Code Quality report.

Why Code Quality and not the SAST / Dependency Scanning report formats: those
are rendered only by GitLab Ultimate. Code Quality is available on CE Free and
shows up inline in the merge request diff, which makes it the only way to put
security findings in front of a reviewer on a self-hosted CE instance.

Reads whichever of these exist in the working directory and merges them:

    trivy-*.json     Trivy JSON  (vulnerabilities, misconfigurations, secrets)
    semgrep.json     Semgrep JSON
    gitleaks.json    Gitleaks JSON

Writes gl-code-quality-report.json, and exits non-zero if any finding is at or
above the severity named by SECURITY_FAIL_ON (empty = never fail).
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import sys

# GitLab Code Quality severities, ordered from worst to least bad.
ORDER = ["blocker", "critical", "major", "minor", "info"]

TRIVY_SEVERITY = {
    "CRITICAL": "blocker",
    "HIGH": "critical",
    "MEDIUM": "major",
    "LOW": "minor",
    "UNKNOWN": "info",
}
SEMGREP_SEVERITY = {"ERROR": "critical", "WARNING": "major", "INFO": "minor"}


def fingerprint(*parts: object) -> str:
    """Stable across runs so GitLab can tell a new finding from an old one."""
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def issue(description, check_name, severity, path, line, fp) -> dict:
    return {
        "type": "issue",
        "description": description,
        "check_name": check_name,
        "severity": severity,
        "fingerprint": fp,
        "location": {"path": path, "lines": {"begin": max(1, int(line or 1))}},
    }


def load(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"  skipping {path}: {exc}", file=sys.stderr)
        return None


def from_trivy(doc) -> list[dict]:
    out = []
    for result in (doc or {}).get("Results") or []:
        target = result.get("Target") or "unknown"

        for v in result.get("Vulnerabilities") or []:
            fix = (
                f" (fixed in {v['FixedVersion']})"
                if v.get("FixedVersion")
                else " (no fix available)"
            )
            out.append(
                issue(
                    f"{v.get('VulnerabilityID')}: {v.get('PkgName')} "
                    f"{v.get('InstalledVersion')} — {v.get('Title') or 'no title'}{fix}",
                    v.get("VulnerabilityID", "trivy-vuln"),
                    TRIVY_SEVERITY.get(v.get("Severity", "UNKNOWN"), "info"),
                    target,
                    1,
                    fingerprint(target, v.get("VulnerabilityID"), v.get("PkgName"),
                                v.get("InstalledVersion")),
                )
            )

        for m in result.get("Misconfigurations") or []:
            line = (m.get("CauseMetadata") or {}).get("StartLine") or 1
            out.append(
                issue(
                    f"{m.get('ID')}: {m.get('Title')} — {m.get('Message')}",
                    m.get("ID", "trivy-config"),
                    TRIVY_SEVERITY.get(m.get("Severity", "UNKNOWN"), "info"),
                    target,
                    line,
                    fingerprint(target, m.get("ID"), line),
                )
            )

        # A secret in the tree has no "wait for a fix" state, only "revoke it".
        for s in result.get("Secrets") or []:
            out.append(
                issue(
                    f"secret detected: {s.get('Title')} ({s.get('RuleID')})",
                    s.get("RuleID", "trivy-secret"),
                    "blocker",
                    target,
                    s.get("StartLine") or 1,
                    fingerprint(target, s.get("RuleID"), s.get("StartLine")),
                )
            )
    return out


def from_semgrep(doc) -> list[dict]:
    out = []
    for r in (doc or {}).get("results") or []:
        extra = r.get("extra") or {}
        path = r.get("path") or "unknown"
        line = (r.get("start") or {}).get("line") or 1
        out.append(
            issue(
                f"{r.get('check_id')}: {extra.get('message', '').strip()}",
                r.get("check_id", "semgrep"),
                SEMGREP_SEVERITY.get(extra.get("severity", "INFO"), "info"),
                path,
                line,
                fingerprint(path, r.get("check_id"), line),
            )
        )
    return out


def from_gitleaks(doc) -> list[dict]:
    out = []
    for f in doc or []:
        commit = (f.get("Commit") or "")[:8]
        path = f.get("File") or "unknown"
        line = f.get("StartLine") or 1
        out.append(
            issue(
                f"secret in history: {f.get('Description')} — commit {commit} "
                f"by {f.get('Author', 'unknown')}",
                f.get("RuleID", "gitleaks"),
                "blocker",
                path,
                line,
                fingerprint(path, f.get("RuleID"), f.get("Commit"), line),
            )
        )
    return out


def main() -> int:
    findings: list[dict] = []
    seen: set[str] = set()

    sources = [(p, from_trivy) for p in sorted(glob.glob("trivy-*.json"))]
    sources += [("semgrep.json", from_semgrep), ("gitleaks.json", from_gitleaks)]

    for path, parser in sources:
        if not os.path.exists(path):
            continue
        doc = load(path)
        if doc is None:
            continue
        produced = parser(doc)
        print(f"  {path}: {len(produced)} finding(s)")
        for f in produced:
            if f["fingerprint"] in seen:
                continue
            seen.add(f["fingerprint"])
            findings.append(f)

    findings.sort(key=lambda f: (ORDER.index(f["severity"]), f["location"]["path"]))

    with open("gl-code-quality-report.json", "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ORDER}
    print("\ntotal: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n))
    print(f"wrote gl-code-quality-report.json ({len(findings)} finding(s))")

    gate = (os.environ.get("SECURITY_FAIL_ON") or "").strip().lower()
    if not gate:
        return 0
    if gate not in ORDER:
        print(f"SECURITY_FAIL_ON={gate!r} is not one of {ORDER}", file=sys.stderr)
        return 2
    limit = ORDER.index(gate)
    blocking = [f for f in findings if ORDER.index(f["severity"]) <= limit]
    if blocking:
        print(f"\n{len(blocking)} finding(s) at or above '{gate}':")
        for f in blocking[:40]:
            loc = f["location"]
            print(f"  {f['severity']:8} {loc['path']}:{loc['lines']['begin']}  {f['check_name']}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
