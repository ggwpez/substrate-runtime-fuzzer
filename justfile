ssh := "scaleway"
repo := "/home/ubuntu/substrate-runtime-fuzzer"
target := "asset-hub-polkadot"
log_file := "/tmp/fuzzer_daemon_stdout.log"

# Show available recipes
default:
    @just --list

# ── Logs ─────────────────────────────────────────────────────────────

# Tail the daemon log (live)
log:
    ssh {{ssh}} 'tail -f {{log_file}}'

# Show last N lines of daemon log (default 50)
log-last n="50":
    ssh {{ssh}} 'tail -{{n}} {{log_file}}'

# Tail the AFL fuzzer log (live)
log-afl:
    ssh {{ssh}} 'tail -f {{repo}}/runtimes/{{target}}/output/{{target}}-fuzzer/logs/afl.log'

# Show the crash log
crashes:
    @ssh {{ssh}} 'cat {{repo}}/scripts/crashes.log 2>/dev/null || echo "No crashes yet"'

# ── Control ──────────────────────────────────────────────────────────

# Show daemon and AFL process status
status:
    @ssh {{ssh}} 'echo "== daemon ==" && (pgrep -a -f fuzzer_daemon.py | grep -v pgrep || echo "  not running") && echo "== afl ==" && echo -n "  instances: " && (pgrep -c -f afl-fuzz 2>/dev/null || echo 0)'

# Stop the daemon and all fuzzer processes
stop:
    -ssh {{ssh}} 'pkill -f fuzzer_daemon.py; pkill -f cargo-ziggy; pkill -INT -f afl-fuzz; sleep 2; pkill -9 -f afl-fuzz; true'
    @echo "Stopped."

# Start the daemon (assumes it's not already running)
start:
    ssh -f {{ssh}} 'cd {{repo}} && nohup python3 scripts/fuzzer_daemon.py scripts/config.toml > {{log_file}} 2>&1 &'
    @sleep 2
    @echo "Started. Run 'just log' to follow output."

# Stop then start
restart: stop start

# ── Deploy ───────────────────────────────────────────────────────────

# Copy local scripts to the server
deploy:
    scp scripts/fuzzer_daemon.py scripts/config.toml scripts/handle_failure.py scripts/setup_server.sh {{ssh}}:{{repo}}/scripts/
    @echo "Deployed."

# Deploy scripts and restart the daemon
redeploy: deploy restart

# ── Setup (one-time) ─────────────────────────────────────────────────

# Run the full server setup (packages, rust, tools, build)
setup:
    scp scripts/setup_server.sh scripts/config.toml {{ssh}}:/tmp/
    ssh {{ssh}} 'bash /tmp/setup_server.sh /tmp/config.toml'

# Configure AFL system settings (needs sudo, survives until reboot)
setup-afl:
    ssh {{ssh}} 'echo core | sudo tee /proc/sys/kernel/core_pattern && sudo bash -c "source ~/.cargo/env && cargo afl system-config"'

# Clear the crash log and test crash files
clean-crashes:
    ssh {{ssh}} 'rm -f {{repo}}/scripts/crashes.log && rm -f {{repo}}/runtimes/{{target}}/output/crashes/test_crash_*'
    @echo "Crash log cleared."

# Clean up orphaned shared memory segments from previous AFL runs
clean-shm:
    ssh {{ssh}} "ipcs -m | awk '\$3 == \"$$USER\" {print \$2}' | xargs -r -I{} ipcrm -m {} 2>/dev/null; echo 'Cleaned.'"
