#!/usr/bin/env bash
set -euo pipefail

# One-time Debian server provisioning for substrate-runtime-fuzzer.
# Usage: ./setup_server.sh [config.toml]
# Run this on the target server (or via ssh).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${1:-$SCRIPT_DIR/config.toml}"

# ---------- helpers ----------------------------------------------------------

log() { echo "[setup] $*"; }

read_toml_value() {
    # Minimal TOML value reader: read_toml_value <file> <key>
    # Handles simple key = "value" lines.
    local file="$1" key="$2"
    grep -E "^\s*${key}\s*=" "$file" | head -1 | sed 's/.*=\s*"\([^"]*\)".*/\1/'
}

# ---------- read config ------------------------------------------------------

if [[ ! -f "$CONFIG" ]]; then
    log "Config not found at $CONFIG, using defaults"
    REPO_DIR="/root/substrate-runtime-fuzzer"
    TARGET="asset-hub-polkadot"
    GIT_BRANCH="main"
else
    log "Reading config from $CONFIG"
    REPO_DIR="$(read_toml_value "$CONFIG" repo_dir)"
    TARGET="$(read_toml_value "$CONFIG" target)"
    GIT_BRANCH="$(read_toml_value "$CONFIG" git_branch)"
    REPO_DIR="${REPO_DIR:-/root/substrate-runtime-fuzzer}"
    TARGET="${TARGET:-asset-hub-polkadot}"
    GIT_BRANCH="${GIT_BRANCH:-main}"
fi

log "repo_dir=$REPO_DIR  target=$TARGET  git_branch=$GIT_BRANCH"

# ---------- 1. System packages -----------------------------------------------

log "Installing system packages..."
apt-get update
apt-get install -y \
    build-essential git curl clang llvm pkg-config libssl-dev \
    python3 python3-pip

# ---------- 2. Rust toolchain ------------------------------------------------

if ! command -v rustup &>/dev/null; then
    log "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    log "Rust already installed, updating..."
    rustup update
fi

rustup default nightly
rustup target add wasm32-unknown-unknown

# ---------- 3. Cargo tools ---------------------------------------------------

install_cargo_tool() {
    local tool="$1"
    if cargo install --list | grep -q "^${tool} "; then
        log "$tool already installed, skipping"
    else
        log "Installing $tool..."
        cargo install "$tool"
    fi
}

install_cargo_tool ziggy
install_cargo_tool cargo-afl
install_cargo_tool honggfuzz
install_cargo_tool grcov

# ---------- 4. Clone / update repo -------------------------------------------

if [[ -d "$REPO_DIR/.git" ]]; then
    log "Repo exists at $REPO_DIR, pulling latest..."
    cd "$REPO_DIR"
    git pull --rebase || {
        log "git pull failed, trying stash approach..."
        git stash
        git pull --rebase
        git stash pop || true
    }
else
    log "Cloning repo into $REPO_DIR..."
    git clone https://github.com/srlabs/substrate-runtime-fuzzer.git "$REPO_DIR"
    cd "$REPO_DIR"
fi

# ---------- 5. Modify Cargo.toml: tag -> branch ------------------------------

CARGO_TOML="$REPO_DIR/runtimes/Cargo.toml"
log "Updating $CARGO_TOML: tag = \"v...\" -> branch = \"$GIT_BRANCH\""

python3 -c "
import re, sys

path = sys.argv[1]
branch = sys.argv[2]

with open(path, 'r') as f:
    content = f.read()

# Replace tag = \"v...\" with branch = \"main\" on lines with polkadot-fellows/runtimes.git
new_content = re.sub(
    r'(polkadot-fellows/runtimes\.git[^}]*?)tag\s*=\s*\"v[^\"]*\"',
    r'\1branch = \"' + branch + r'\"',
    content
)

if content != new_content:
    with open(path, 'w') as f:
        f.write(new_content)
    print(f'Updated Cargo.toml to use branch = \"{branch}\"')
else:
    print('Cargo.toml already uses branch references, no changes needed')
" "$CARGO_TOML" "$GIT_BRANCH"

# ---------- 6. Initial build -------------------------------------------------

log "Building fuzzer for $TARGET..."
cd "$REPO_DIR/runtimes/$TARGET"
SKIP_WASM_BUILD=1 cargo ziggy build

# ---------- 7. Done ----------------------------------------------------------

log ""
log "============================================="
log "  Setup complete!"
log "============================================="
log ""
log "To run the fuzzer daemon manually:"
log "  cd $REPO_DIR && python3 scripts/fuzzer_daemon.py scripts/config.toml"
log ""
log "To run as a systemd service, create /etc/systemd/system/fuzzer.service:"
log "  [Unit]"
log "  Description=Substrate Runtime Fuzzer Daemon"
log "  After=network.target"
log ""
log "  [Service]"
log "  Type=simple"
log "  WorkingDirectory=$REPO_DIR"
log "  ExecStart=/usr/bin/python3 $REPO_DIR/scripts/fuzzer_daemon.py $REPO_DIR/scripts/config.toml"
log "  Restart=on-failure"
log "  RestartSec=60"
log ""
log "  [Install]"
log "  WantedBy=multi-user.target"
log ""
log "Then: systemctl daemon-reload && systemctl enable --now fuzzer"
