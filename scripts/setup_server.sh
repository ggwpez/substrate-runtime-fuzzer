#!/usr/bin/env bash
set -euo pipefail

# One-time Debian/Ubuntu server provisioning for substrate-runtime-fuzzer.
#
# Usage:  ssh <server> 'bash -s' < setup_server.sh
#    or:  just setup
#
# This script handles EVERYTHING:
#   1. System packages (apt)
#   2. Rust nightly + wasm target
#   3. Cargo tools (ziggy, cargo-afl, honggfuzz, grcov)
#   4. AFL runtime build + system tuning (core_pattern, afl-system-config)
#   5. Clone/update the repo
#   6. Patch Cargo.toml (tag -> branch = "main")
#   7. Full build
#
# The script splits work between root (apt, sysctl) and the invoking user
# (rust, cargo, repo) so nothing ends up owned by the wrong user.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo /tmp)"

# ---------- defaults (override via config.toml) ------------------------------

REPO_DIR="${HOME}/substrate-runtime-fuzzer"
TARGET="asset-hub-polkadot"
GIT_REF="main"
CLONE_URL="https://github.com/ggwpez/substrate-runtime-fuzzer.git"

read_toml_value() {
    local file="$1" key="$2"
    grep -E "^\s*${key}\s*=" "$file" 2>/dev/null | head -1 | sed 's/.*=\s*"\([^"]*\)".*/\1/'
}

# Try to read config if it exists alongside the script
CONFIG="${1:-$SCRIPT_DIR/config.toml}"
if [[ -f "$CONFIG" ]]; then
    echo "[setup] Reading config from $CONFIG"
    _v=$(read_toml_value "$CONFIG" repo_dir);   [[ -n "$_v" ]] && REPO_DIR="$_v"
    _v=$(read_toml_value "$CONFIG" target);      [[ -n "$_v" ]] && TARGET="$_v"
    _v=$(read_toml_value "$CONFIG" git_ref);      [[ -n "$_v" ]] && GIT_REF="$_v"
fi

log() { echo "[setup] $*"; }
log "repo_dir=$REPO_DIR  target=$TARGET  branch=$GIT_REF  user=$(whoami)"

# ---------- 1. System packages (needs sudo) ----------------------------------

log "Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    build-essential git curl clang llvm pkg-config libssl-dev \
    python3 python3-pip >/dev/null

# ---------- 2. AFL system tuning (needs sudo) --------------------------------

log "Configuring core_pattern for AFL..."
echo core | sudo tee /proc/sys/kernel/core_pattern >/dev/null

# Make it persistent across reboots
if ! grep -q 'kernel.core_pattern' /etc/sysctl.conf 2>/dev/null; then
    echo 'kernel.core_pattern=core' | sudo tee -a /etc/sysctl.conf >/dev/null
fi

# ---------- 3. Rust toolchain ------------------------------------------------

if ! command -v rustup &>/dev/null; then
    log "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
source "$HOME/.cargo/env"

log "Setting nightly as default toolchain..."
rustup default nightly
rustup target add wasm32-unknown-unknown
log "rustc: $(rustc --version)"

# ---------- 4. Cargo tools ---------------------------------------------------

install_cargo_tool() {
    local tool="$1"
    if cargo install --list 2>/dev/null | grep -q "^${tool} "; then
        log "$tool already installed"
    else
        log "Installing $tool..."
        cargo install "$tool"
    fi
}

install_cargo_tool ziggy
install_cargo_tool cargo-afl
install_cargo_tool honggfuzz
install_cargo_tool grcov

# ---------- 5. Build AFL runtime + system config ------------------------------

log "Building AFL runtime for $(rustc --version)..."
cargo afl config --build --force

log "Running AFL system config (may need sudo)..."
cargo afl system-config || log "afl system-config failed (non-fatal, may need manual sudo)"

# ---------- 6. Clone / update repo -------------------------------------------

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
    git clone "$CLONE_URL" "$REPO_DIR"
    cd "$REPO_DIR"
fi

# ---------- 7. Patch Cargo.toml git ref ----------------------------------------

CARGO_TOML="$REPO_DIR/runtimes/Cargo.toml"
log "Patching Cargo.toml to use git_ref = \"$GIT_REF\""

python3 -c "
import re, sys
path, ref = sys.argv[1], sys.argv[2]
is_tag = bool(re.match(r'^v\d', ref))
new_key = f'tag = \"{ref}\"' if is_tag else f'branch = \"{ref}\"'
with open(path) as f: content = f.read()
new = re.sub(
    r'(polkadot-fellows/runtimes\.git[^}]*?)(?:tag|branch)\s*=\s*\"[^\"]*\"',
    r'\1' + new_key, content)
if content != new:
    with open(path, 'w') as f: f.write(new)
    print(f'  Patched to {new_key}')
else:
    print(f'  Already uses {new_key}')
" "$CARGO_TOML" "$GIT_REF"

# ---------- 8. Initial build --------------------------------------------------

log "Building fuzzer for $TARGET (this takes a few minutes)..."
cd "$REPO_DIR/runtimes/$TARGET"
SKIP_WASM_BUILD=1 cargo ziggy build

# ---------- 9. Done -----------------------------------------------------------

log ""
log "============================================="
log "  Setup complete!"
log "============================================="
log ""
log "Start the daemon:"
log "  cd $REPO_DIR && python3 scripts/fuzzer_daemon.py scripts/config.toml"
log ""
log "Or from your local machine:"
log "  just start        # start daemon"
log "  just log          # tail logs"
log "  just redeploy     # deploy scripts + restart"
log "  just status       # check processes"
