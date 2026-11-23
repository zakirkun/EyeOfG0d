#!/usr/bin/env python3
"""Regenerate db/vulnclass_table.go from the knowledge corpus.

This mirrors knowledge.buildClassIndex exactly:
  - canonical classes = every ontology category name and child, plus every
    A-to-B signal id, all normalised;
  - an alias is claimed by a signal keyword or an ontology synonym;
  - an alias that is itself canonical is never rewritten;
  - an alias claimed by more than one class is dropped, never guessed.

Run from the repository root:
    python scripts/gen_vulnclass_table.py
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ONTOLOGY = ROOT / "knowledge" / "data" / "vuln_ontology.json"
SIGNALS = ROOT / "knowledge" / "data" / "ab_signals.json"
OUT = ROOT / "db" / "vulnclass_table.go"


def norm(s: str) -> str:
    """Match normClassToken: lowercase, collapse every run of non-alphanumerics."""
    return re.sub(r"[^a-z0-9]+", "_", s.strip().lower()).strip("_")


def main() -> int:
    ontology = json.loads(ONTOLOGY.read_text(encoding="utf-8"))
    signals = json.loads(SIGNALS.read_text(encoding="utf-8"))

    categories = ontology["categories"]
    sig_list = signals.get("signals", [])

    classes = set()
    for name, cat in categories.items():
        classes.add(norm(name))
        for child in cat.get("children", []):
            classes.add(norm(child))
    for sig in sig_list:
        classes.add(norm(sig["id"]))

    claims: dict[str, set[str]] = {}

    def claim(alias: str, target: str) -> None:
        if not alias or alias in classes or not target:
            return
        claims.setdefault(alias, set()).add(target)

    for sig in sig_list:
        sid = norm(sig["id"])
        for kw in sig.get("keywords", []):
            claim(norm(kw), sid)

    for name, cat in categories.items():
        cat_token = norm(name)
        children = [norm(c) for c in cat.get("children", [])]
        for syn in cat.get("synonyms", []):
            n = norm(syn)
            if not n or n in classes:
                continue
            hit = n if n in children else cat_token
            claim(n, hit)

    aliases = {a: next(iter(t)) for a, t in claims.items() if len(t) == 1}

    lines = [
        "// Code generated from the ARTEX knowledge corpus. DO NOT EDIT.",
        "//",
        "// Source: knowledge/data/vuln_ontology.json + knowledge/data/ab_signals.json",
        "// (branch feat/airecon-knowledge-and-skills). The alias derivation mirrors",
        "// knowledge.buildClassIndex: an alias is a signal keyword that is not itself a",
        "// canonical class and that names exactly one target class.",
        "//",
        "// This table exists only because that corpus is not on main yet. When it lands,",
        "// delete this file and point canonicalVulnClass at knowledge.Class - the call",
        "// site does not otherwise change.",
        "",
        "package db",
        "",
        "// canonicalVulnClasses is every class token the corpus defines.",
        "var canonicalVulnClasses = map[string]bool{",
    ]
    for c in sorted(classes):
        lines.append(f'\t"{c}": true,')
    lines.append("}")
    lines.append("")
    lines.append("// vulnClassAliases folds an unambiguous alias onto its canonical class.")
    lines.append("var vulnClassAliases = map[string]string{")
    for a in sorted(aliases):
        lines.append(f'\t"{a}": "{aliases[a]}",')
    lines.append("}")
    lines.append("")

    OUT.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    # The committed file is gofmt'd (which aligns the map literals). Without this
    # step a regeneration produces a large, purely cosmetic diff, which makes it
    # hard to see what actually changed.
    if shutil.which("gofmt"):
        subprocess.run(["gofmt", "-w", str(OUT)], check=True)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(classes)} classes, {len(aliases)} aliases")
    return 0


if __name__ == "__main__":
    sys.exit(main())