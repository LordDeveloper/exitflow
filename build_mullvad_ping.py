#!/usr/bin/env python3
"""Build a one-file mullvad-ping binary with embedded relays.json."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "mullvad-ping.py"
RELAYS_SRC = ROOT / "storage" / "relays.json"
RELAYS_COPY = ROOT / "relays.json"
DIST = ROOT / "dist"
BUILD = ROOT / "build" / "mullvad-ping"
SPEC = ROOT / "mullvad-ping.spec"


def main() -> int:
    if not SCRIPT.is_file():
        print(f"Missing {SCRIPT}", file=sys.stderr)
        return 1
    if not RELAYS_SRC.is_file():
        print(f"Missing {RELAYS_SRC}", file=sys.stderr)
        return 1

    shutil.copy2(RELAYS_SRC, RELAYS_COPY)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"])

    # Windows uses ; as the add-data separator, Unix uses :
    sep = ";" if os.name == "nt" else ":"
    add_data = f"{RELAYS_COPY}{sep}."

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "mullvad-ping",
        "--add-data",
        add_data,
        "--distpath",
        str(DIST),
        "--workpath",
        str(BUILD),
        "--specpath",
        str(ROOT),
        str(SCRIPT),
    ]
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd)

    binary = DIST / ("mullvad-ping.exe" if os.name == "nt" else "mullvad-ping")
    if not binary.is_file():
        print("Build finished but binary was not found.", file=sys.stderr)
        return 1

    size_mb = binary.stat().st_size / (1024 * 1024)
    print(f"Built {binary} ({size_mb:.1f} MB)")
    print("relays.json is embedded inside the binary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
