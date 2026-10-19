#!/usr/bin/env python3
"""CLI surface smoke check.

Exits non-zero if any of the analyzer's read-only informational invocations
misbehaves. Those are the commands that cost nothing to run and that everything
else depends on working: --version proving the binary can start and identify
itself, --help and the two listing commands proving argument parsing and the
phase/pipeline catalog are intact.

None of these touch a sample, a config, or the network. That is the point - a
smoke test that has side effects cannot be run casually, and the one that should
be run casually is this one.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TIMEOUT = 60

CASES = [
    (["--version"], "identity", True),
    (["--help"], "help", True),
    (["--list-phases"], "phase catalog", True),
    (["--list-pipelines"], "pipeline catalog", True),
]


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    exe = repo / "build-ucrt" / "static_analyzer.exe"
    if not exe.is_file():
        print(f"selftest: {exe.name} is not built", file=sys.stderr)
        return 1

    failures = 0
    for argv, label, _expect_text in CASES:
        try:
            out = subprocess.run(
                [str(exe), *argv], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=TIMEOUT,
                check=False, cwd=str(repo),
            )
        except subprocess.TimeoutExpired:
            print(f"  FAIL  {label:18} timed out after {TIMEOUT}s")
            failures += 1
            continue
        except OSError as exc:
            print(f"  FAIL  {label:18} could not run: {exc}")
            failures += 1
            continue

        text = (out.stdout or "") + (out.stderr or "")
        # The tracer announces itself on stderr before main() runs, so stderr is
        # never expected to be empty. stdout is.
        if out.returncode != 0:
            print(f"  FAIL  {label:18} exited {out.returncode}")
            failures += 1
        elif not (out.stdout or "").strip():
            print(f"  FAIL  {label:18} produced no output")
            failures += 1
        else:
            first = out.stdout.strip().splitlines()[0][:60]
            print(f"  ok    {label:18} {first}")

    print()
    print(f"selftest: {len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())