#!/usr/bin/env python3
"""
Re-embed scripts/to-codequality.py into the .codequality_converter block of
security.gitlab-ci.yml.

The converter has to be inline so the template can be included on its own —
`include:` brings YAML, not files — but a copy-pasted script drifts. This keeps
one source of truth and regenerates the copy.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "to-codequality.py"
TEMPLATE = ROOT / "security.gitlab-ci.yml"
INDENT = " " * 6

MARKER = re.compile(
    r"(?ms)^\.codequality_converter:\n  script:\n    - \|\n"
    r"      cat > to-codequality\.py <<'PYEOF'\n.*?^      PYEOF\n"
)


def main() -> int:
    src = SCRIPT.read_text(encoding="utf-8").rstrip("\n")
    body = "\n".join(INDENT + l if l.strip() else "" for l in src.split("\n"))
    block = (
        ".codequality_converter:\n  script:\n    - |\n"
        f"{INDENT}cat > to-codequality.py <<'PYEOF'\n"
        f"{body}\n{INDENT}PYEOF\n"
    )
    text = TEMPLATE.read_text(encoding="utf-8")
    if not MARKER.search(text):
        print("could not find the .codequality_converter block", file=sys.stderr)
        return 1
    new = MARKER.sub(lambda _: block, text, count=1)
    if new == text:
        print("already in sync")
        return 0
    TEMPLATE.write_text(new, encoding="utf-8")
    print(f"re-embedded {len(src.splitlines())} lines into {TEMPLATE.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
