"""Fetch / refresh the public fingerprint database into vendor/ (not committed: GPL-3.0).

    python scripts/update_fingerprints.py

Source: https://github.com/enthec/webappanalyzer - community-maintained continuation of
the Wappalyzer rule set after Wappalyzer went closed-source (2023). Our own rules live in
config/custom_fingerprints.json and are merged on top at load time.
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "vendor" / "webappanalyzer"
REPO = "https://github.com/enthec/webappanalyzer.git"


def main() -> int:
    if (DEST / ".git").exists():
        subprocess.run(["git", "-C", str(DEST), "pull", "--ff-only", "-q"], check=True)
    else:
        if DEST.exists():
            shutil.rmtree(DEST)
        DEST.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", "-q", REPO, str(DEST)], check=True)
    rev = subprocess.run(["git", "-C", str(DEST), "log", "-1", "--format=%h %cd"], capture_output=True, text=True).stdout.strip()
    n = len(list((DEST / "src" / "technologies").glob("*.json")))
    print(f"fingerprints at {rev} ({n} files) -> {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
