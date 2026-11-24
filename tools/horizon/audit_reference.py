"""Offline source preflight; never authorizes production browsing."""
import argparse
import json
from pathlib import Path
import re
import subprocess


RISK_FLAGS = ("--no-sandbox", "--single-process", "--no-zygote",
              "--disable-component-update", "--ignore-certificate-errors")
SCRIPTS = ("gx/build-chromium.sh", "gx/build-nx.sh", "gx/host_nx.c")


def audit(root, expected_revision):
    revision = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain"], text=True).strip())
    missing, findings = [], []
    for name in SCRIPTS:
        path = root / name
        if not path.is_file():
            missing.append(name)
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for flag in RISK_FLAGS:
                if re.search(re.escape(flag) + r"(?![\w-])", line):
                    findings.append({"file": name, "line": number, "flag": flag})
    return {"revision": revision, "expected_revision": expected_revision,
            "dirty": dirty, "missing": missing, "risk_flags": findings,
            "source_gate_pass": revision == expected_revision and not dirty
            and not missing and not findings,
            "production_browsing_approved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("--revision must be a full lowercase commit SHA")
    try:
        report = audit(args.reference, args.revision)
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        parser.exit(2, f"audit failed: {exc}\n")
    print(json.dumps(report, indent=2))
    return 0 if report["source_gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
