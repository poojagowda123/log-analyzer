#!/usr/bin/env python3
"""Run the project's `src/*.py` scripts sequentially and print a summary.

Place this file in the project root and it will run the scripts found in
the `src/` directory using the same Python interpreter that launched this
process.
"""
from pathlib import Path
import subprocess
import sys
import os
import io

# Ensure this process uses UTF-8 for stdout/stderr so prints of
# captured UTF-8 output won't raise UnicodeEncodeError on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Scripts to run (relative to the `src/` directory)
SCRIPTS = [
    "parse_logs.py",
    "parse_windows_logs.py",
    "read_logs.py",
    "read_windows_logs.py",
    "parse_usb_logs.py",
    "detect_suspicious.py",
    "detect_usb_suspicious.py",
    "ml_anomaly_detection.py",
    "train_usb_model.py",
    "generate_readable_report.py",
]


def main() -> int:
    # The orchestrator lives in the repo root; the Python scripts are in src/
    root = Path(__file__).resolve().parent / "src"
    python = sys.executable
    results = []

    for name in SCRIPTS:
        path = root / name
        if not path.exists():
            msg = f"SKIP: {name} (not found: {path})"
            print(msg)
            results.append((name, False, msg))
            continue

        print(f"\n=== Running {name} ===")
        env = os.environ.copy()
        env.setdefault("PYTHONIOENCODING", "utf-8")
        proc = subprocess.run(
            [python, str(path)],
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
        )

        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()

        skipped = False
        skip_reason = None
        if proc.returncode != 0:
            low = stderr.lower()
            if "no such file or directory" in low or "filenotfounderror" in low:
                skipped = True
                skip_reason = "missing input file"
            if "a required privilege is not held by the client" in low or "required privilege" in low:
                skipped = True
                skip_reason = "insufficient privileges to read Windows event log"

        header = f"Return code: {proc.returncode}"
        print(header)
        if stdout:
            print("-- stdout --")
            print(stdout)
        if stderr:
            print("-- stderr --")
            print(stderr)

        if skipped:
            print(f"SKIPPED {name}: {skip_reason}")
            results.append((name, "SKIPPED", skip_reason))
        else:
            ok = proc.returncode == 0
            results.append((name, "OK" if ok else "FAIL", proc.returncode))

    # Summary
    print("\n=== Summary ===")
    for name, status, info in results:
        if status == "OK":
            print(f"{name}: OK (rc={info})")
        elif status == "SKIPPED":
            print(f"{name}: SKIPPED ({info})")
        else:
            print(f"{name}: FAIL (rc={info})")

    any_fail = any(status == "FAIL" for _, status, _ in results)
    return 2 if any_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
