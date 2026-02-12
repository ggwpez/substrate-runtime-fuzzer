#!/usr/bin/env python3
"""
Continuous fuzzing daemon for substrate-runtime-fuzzer.

Runs cargo ziggy fuzz in a loop, periodically stopping to update
git dependencies and rebuild. Monitors for crashes and reports them
via a configurable handler script.

Usage: fuzzer_daemon.py [config.toml]
"""

import logging
import logging.handlers
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "server": {"ssh_target": "scaleway"},
    "fuzzer": {
        "target": "asset-hub-polkadot",
        "jobs": 0,
        "extra_args": "--no-honggfuzz",
        "repo_dir": "/root/substrate-runtime-fuzzer",
    },
    "updates": {
        "interval_hours": 168,
        "git_remote": "https://github.com/polkadot-fellows/runtimes.git",
        "git_ref": "main",
    },
    "reporting": {
        "failure_script": "./handle_failure.py",
        "crash_log": "crashes.log",
    },
}


def load_config(path: str) -> dict:
    """Load config.toml. Uses tomllib on 3.11+, falls back to manual parsing."""
    if not os.path.isfile(path):
        logging.warning("Config file %s not found, using defaults", path)
        return DEFAULT_CONFIG

    try:
        import tomllib

        with open(path, "rb") as f:
            return tomllib.load(f)
    except ImportError:
        pass

    # Manual TOML parser for Python < 3.11 (handles only our simple format)
    config: dict = {}
    current_section: dict = {}
    current_key = ""

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Section header
            section_match = re.match(r"^\[(\w+)\]$", line)
            if section_match:
                current_key = section_match.group(1)
                current_section = {}
                config[current_key] = current_section
                continue

            # Key = value
            kv_match = re.match(r'^(\w+)\s*=\s*(.+?)(\s*#.*)?$', line)
            if kv_match:
                key = kv_match.group(1)
                raw_value = kv_match.group(2).strip()

                # Parse value type
                if raw_value.startswith('"') and raw_value.endswith('"'):
                    value = raw_value[1:-1]
                elif raw_value.isdigit():
                    value = int(raw_value)
                elif raw_value.replace(".", "", 1).isdigit():
                    value = float(raw_value)
                elif raw_value.lower() in ("true", "false"):
                    value = raw_value.lower() == "true"
                else:
                    value = raw_value

                current_section[key] = value

    return config


def get_config(config: dict, section: str, key: str, default=None):
    """Safely get a config value with a fallback to DEFAULT_CONFIG."""
    value = config.get(section, {}).get(key)
    if value is not None:
        return value
    return DEFAULT_CONFIG.get(section, {}).get(key, default)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(repo_dir: str):
    """Configure logging to stderr + rotating file."""
    log = logging.getLogger()
    log.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # stderr handler (captured by systemd journal)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    log.addHandler(stderr_handler)

    # Rotating file handler
    log_file = os.path.join(repo_dir, "fuzzer_daemon.log")
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)


# ---------------------------------------------------------------------------
# Cargo.toml modification
# ---------------------------------------------------------------------------

def _is_tag_ref(ref: str) -> bool:
    """Check if a git ref looks like a tag (e.g. v1.2.3)."""
    return bool(re.match(r"^v\d", ref))


def modify_cargo_toml_git_ref(cargo_toml_path: str, git_ref: str) -> bool:
    """Update polkadot-fellows/runtimes.git deps to use the given git ref.

    Detects whether git_ref is a tag (v1.2.3) or branch name and sets
    the appropriate Cargo.toml key (tag = "..." or branch = "...").
    """
    with open(cargo_toml_path, "r") as f:
        content = f.read()

    is_tag = _is_tag_ref(git_ref)
    new_key = f'tag = "{git_ref}"' if is_tag else f'branch = "{git_ref}"'

    # Replace any existing tag = "..." or branch = "..." on runtimes.git lines
    new_content = re.sub(
        r'(polkadot-fellows/runtimes\.git[^}]*?)(?:tag|branch)\s*=\s*"[^"]*"',
        rf"\1{new_key}",
        content,
    )

    if content != new_content:
        with open(cargo_toml_path, "w") as f:
            f.write(new_content)
        logging.info("Updated %s to use %s", cargo_toml_path, new_key)
        return True

    logging.info("Cargo.toml already uses %s", new_key)
    return False


# ---------------------------------------------------------------------------
# Update & Build
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], cwd: str = None, env: dict = None, timeout: int = None) -> subprocess.CompletedProcess:
    """Run a command, logging it and returning the result."""
    logging.info("Running: %s (cwd=%s)", " ".join(cmd), cwd or ".")
    merged_env = {**os.environ, **(env or {})}
    result = subprocess.run(
        cmd, cwd=cwd, env=merged_env, capture_output=True, text=True, timeout=timeout
    )
    if result.stdout.strip():
        for line in result.stdout.strip().splitlines():
            logging.debug("  stdout: %s", line)
    if result.stderr.strip():
        for line in result.stderr.strip().splitlines():
            logging.debug("  stderr: %s", line)
    return result


def update_and_build(config: dict) -> bool:
    """Update runtimes git dep to latest main commit and rebuild."""
    repo_dir = get_config(config, "fuzzer", "repo_dir")
    target = get_config(config, "fuzzer", "target")
    git_ref = get_config(config, "updates", "git_ref")
    runtimes_dir = os.path.join(repo_dir, "runtimes")
    target_dir = os.path.join(runtimes_dir, target)

    # 1. Ensure Cargo.toml points to the configured git ref
    cargo_toml = os.path.join(runtimes_dir, "Cargo.toml")
    modify_cargo_toml_git_ref(cargo_toml, git_ref)

    # 2. cargo update for the target runtime package to pick up latest commit
    runtime_crate = target + "-runtime"
    logging.info("Running cargo update -p %s...", runtime_crate)
    result = run_cmd(["cargo", "update", "-p", runtime_crate], cwd=runtimes_dir)
    if result.returncode != 0:
        logging.error("cargo update failed: %s", result.stderr)
        return False

    # 3. Build
    logging.info("Building fuzzer for %s...", target)
    result = run_cmd(
        ["cargo", "ziggy", "build"],
        cwd=target_dir,
        env={"SKIP_WASM_BUILD": "1"},
        timeout=3600,  # 1 hour max
    )
    if result.returncode != 0:
        logging.error("Build failed: %s", result.stderr)
        return False

    logging.info("Build succeeded")
    return True


# ---------------------------------------------------------------------------
# Crash monitoring
# ---------------------------------------------------------------------------

def monitor_crashes(config: dict, target_dir: str, stop_event: threading.Event):
    """Poll output/crashes/ for new files and call the failure handler."""
    target = get_config(config, "fuzzer", "target")
    failure_script = get_config(config, "reporting", "failure_script")
    crashes_dir = os.path.join(target_dir, "output", "crashes")

    # Resolve failure_script relative to scripts dir
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isabs(failure_script):
        failure_script = os.path.join(scripts_dir, failure_script)

    # Snapshot existing crashes
    known_crashes: set[str] = set()
    if os.path.isdir(crashes_dir):
        known_crashes = set(os.listdir(crashes_dir))
    logging.info("Crash monitor started, %d existing crash files", len(known_crashes))

    while not stop_event.is_set():
        stop_event.wait(30)  # poll every 30 seconds
        if stop_event.is_set():
            break

        if not os.path.isdir(crashes_dir):
            continue

        current_files = set(os.listdir(crashes_dir))
        new_crashes = current_files - known_crashes

        for crash_file in sorted(new_crashes):
            crash_path = os.path.join(crashes_dir, crash_file)
            timestamp = datetime.now(timezone.utc).isoformat()
            logging.warning("NEW CRASH DETECTED: %s", crash_path)

            try:
                run_cmd(
                    [sys.executable, failure_script, crash_path, target, timestamp],
                    cwd=scripts_dir,
                )
            except Exception:
                logging.exception("Failed to run failure script for %s", crash_path)

            known_crashes.add(crash_file)


# ---------------------------------------------------------------------------
# Fuzzer cycle
# ---------------------------------------------------------------------------

def run_fuzzer_cycle(config: dict, duration_hours: float):
    """Run the fuzzer for the given duration, monitoring for crashes."""
    repo_dir = get_config(config, "fuzzer", "repo_dir")
    target = get_config(config, "fuzzer", "target")
    jobs = get_config(config, "fuzzer", "jobs")
    extra_args = get_config(config, "fuzzer", "extra_args")
    target_dir = os.path.join(repo_dir, "runtimes", target)

    # Determine job count
    if jobs == 0:
        try:
            nproc = os.cpu_count() or 2
            jobs = max(1, nproc - 1)
        except Exception:
            jobs = 1
    logging.info("Using %d fuzzing jobs", jobs)

    # Build command
    cmd = ["cargo", "ziggy", "fuzz", "-j", str(jobs)]
    if extra_args:
        cmd.extend(extra_args.split())

    # Clean up stale shared memory segments from previous AFL runs
    subprocess.run("ipcs -m | awk '$3 == \"root\" {print $2}' | xargs -r -I{} ipcrm -m {}", shell=True, capture_output=True)

    logging.info("Starting fuzzer: %s", " ".join(cmd))
    env = {**os.environ, "SKIP_WASM_BUILD": "1"}
    fuzzer_log = os.path.join(target_dir, "fuzzer_output.log")
    fuzzer_log_fh = open(fuzzer_log, "a")
    proc = subprocess.Popen(
        cmd,
        cwd=target_dir,
        env=env,
        stdout=fuzzer_log_fh,
        stderr=fuzzer_log_fh,
    )

    # Start crash monitor thread
    stop_event = threading.Event()
    monitor_thread = threading.Thread(
        target=monitor_crashes,
        args=(config, target_dir, stop_event),
        daemon=True,
    )
    monitor_thread.start()

    # Ziggy may stay alive (TUI mode) or exit after spawning AFL.
    # Either way, we wait for the configured duration then stop everything.
    duration_secs = duration_hours * 3600
    start_time = time.monotonic()
    logging.info("Fuzzer running for %.2f hours (%.0f seconds)", duration_hours, duration_secs)

    try:
        proc.wait(timeout=duration_secs)
        logging.info("Ziggy exited with code %d", proc.returncode)
        # Ziggy exited but AFL instances may still be running — sleep remaining time
        elapsed = time.monotonic() - start_time
        remaining = duration_secs - elapsed
        if remaining > 0:
            afl_count = _count_afl_instances(target_dir)
            if afl_count > 0 and proc.returncode == 0:
                logging.info("Ziggy exited but %d AFL instances still running, sleeping %.0fs", afl_count, remaining)
                time.sleep(remaining)
    except subprocess.TimeoutExpired:
        # Duration elapsed, stop ziggy and AFL
        logging.info("Fuzzing duration elapsed, stopping...")
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # Always clean up AFL instances
    _stop_afl_instances(target_dir)
    fuzzer_log_fh.close()

    # Stop crash monitor
    stop_event.set()
    monitor_thread.join(timeout=10)

    return 0


def _count_afl_instances(target_dir: str) -> int:
    """Count running afl-fuzz processes for this target."""
    try:
        result = subprocess.run(
            ["pgrep", "-c", "-f", "afl-fuzz.*" + os.path.basename(target_dir)],
            capture_output=True, text=True,
        )
        return int(result.stdout.strip()) if result.returncode == 0 else 0
    except Exception:
        return 0


def _stop_afl_instances(target_dir: str):
    """Send SIGINT to all afl-fuzz processes for this target, then wait."""
    try:
        result = subprocess.run(
            ["pkill", "-INT", "-f", "afl-fuzz.*" + os.path.basename(target_dir)],
            capture_output=True, text=True,
        )
        logging.info("Sent SIGINT to AFL instances (pkill exit: %d)", result.returncode)
    except Exception:
        logging.exception("Failed to send SIGINT to AFL")

    # Wait for processes to exit
    time.sleep(5)

    # Force kill any remaining
    try:
        subprocess.run(
            ["pkill", "-9", "-f", "afl-fuzz.*" + os.path.basename(target_dir)],
            capture_output=True, text=True,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "config.toml"
    )
    config = load_config(config_path)
    repo_dir = get_config(config, "fuzzer", "repo_dir")
    interval_hours = get_config(config, "updates", "interval_hours")

    # Ensure cargo is in PATH (non-interactive shells may not source .cargo/env)
    cargo_bin = os.path.expanduser("~/.cargo/bin")
    if cargo_bin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = cargo_bin + ":" + os.environ.get("PATH", "")

    setup_logging(repo_dir)
    logging.info("=" * 60)
    logging.info("Substrate Runtime Fuzzer Daemon starting")
    logging.info("Config: %s", config_path)
    logging.info("Target: %s", get_config(config, "fuzzer", "target"))
    logging.info("Update interval: %d hours", interval_hours)
    logging.info("=" * 60)

    while True:
        # Update and build
        logging.info("--- Starting update & build cycle ---")
        if update_and_build(config):
            # Run fuzzer for the configured interval
            logging.info("--- Starting fuzzer cycle (%d hours) ---", interval_hours)
            returncode = run_fuzzer_cycle(config, interval_hours)
            if returncode is not None and returncode != 0:
                logging.warning("Fuzzer exited with code %d, restarting cycle", returncode)
        else:
            logging.error("Build failed, sleeping 1 hour before retry")
            time.sleep(3600)
            continue

        logging.info("--- Cycle complete, looping ---")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Daemon interrupted by user, shutting down")
        sys.exit(0)
    except Exception:
        logging.exception("Fatal error in daemon")
        sys.exit(1)
