#!/usr/bin/env python3
"""Append crash info to a log file. Extend this to add webhooks, email, etc."""
import sys
from pathlib import Path


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <crash_file> <target> <timestamp>", file=sys.stderr)
        sys.exit(1)

    crash_file = sys.argv[1]
    target = sys.argv[2]
    timestamp = sys.argv[3]
    log_path = Path(__file__).parent / "crashes.log"

    with open(log_path, "a") as f:
        f.write(f"[{timestamp}] target={target} file={crash_file}\n")

    print(f"Logged crash: {crash_file}")


if __name__ == "__main__":
    main()
