#!/usr/bin/env bash
# Build copy_fail_guard (eBPF program + userspace loader)
# Must run on Linux with: rustup, nightly toolchain, bpf-linker
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/dist"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
info()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }

# --- preflight checks ---
if [ "$(uname -s)" != "Linux" ]; then
    red "Error: must build on Linux"; exit 1
fi

for cmd in cargo rustup; do
    command -v "$cmd" >/dev/null || { red "Error: $cmd not found"; exit 1; }
done

if ! rustup toolchain list | grep -q '^nightly'; then
    info "Installing nightly toolchain..."
    rustup toolchain install nightly --component rust-src
fi

if ! cargo +nightly install --list | grep -q '^bpf-linker'; then
    info "Installing bpf-linker..."
    cargo +nightly install bpf-linker
fi

# --- build eBPF program ---
info "Building eBPF LSM program..."
cargo +nightly build \
    --manifest-path "${ROOT}/crates/copy_fail_guard-ebpf/Cargo.toml" \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

EBPF_BIN="${ROOT}/crates/copy_fail_guard-ebpf/target/bpfel-unknown-none/release/copy_fail_guard"
[ -f "$EBPF_BIN" ] || { red "Error: eBPF binary not found at $EBPF_BIN"; exit 1; }

# --- build userspace loader ---
info "Building userspace loader..."
cargo build --manifest-path "${ROOT}/Cargo.toml" -p copy_fail_guard --release

LOADER_BIN="${ROOT}/target/release/copy_fail_guard"
[ -f "$LOADER_BIN" ] || { red "Error: loader binary not found at $LOADER_BIN"; exit 1; }

# --- assemble dist ---
rm -rf "$OUT"
mkdir -p "$OUT"
cp "$EBPF_BIN"  "$OUT/copy_fail_guard.bpf.o"
cp "$LOADER_BIN" "$OUT/copy_fail_guard"

# --- generate one-click loader script ---
cat > "$OUT/run_guard.sh" << 'LOADER_SCRIPT'
#!/usr/bin/env bash
# One-click loader for copy_fail_guard (CVE-2026-31431 mitigation)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
    red "Error: must run as root (need CAP_BPF + CAP_SYS_ADMIN)"
    echo "Usage: sudo $0"
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    red "Error: Linux required"; exit 1
fi

# Check BPF LSM
if [ -f /sys/kernel/security/lsm ]; then
    if ! grep -q 'bpf' /sys/kernel/security/lsm; then
        red "Error: BPF LSM not enabled in kernel"
        echo "Current LSMs: $(cat /sys/kernel/security/lsm)"
        echo "Add 'bpf' to your kernel boot parameter: lsm=...,bpf"
        exit 1
    fi
fi

green "Starting copy_fail_guard — CVE-2026-31431 mitigation"
echo "  AF_ALG socket creation will be blocked for all userspace processes."
echo "  Press Ctrl-C to stop and detach."
echo ""

exec env GUARD_BPF_OBJ="${DIR}/copy_fail_guard.bpf.o" RUST_LOG=info \
    "${DIR}/copy_fail_guard"
LOADER_SCRIPT

chmod +x "$OUT/run_guard.sh"

green "Build complete. Output in: $OUT/"
echo ""
echo "  dist/"
echo "  ├── copy_fail_guard.bpf.o   # eBPF LSM program"
echo "  ├── copy_fail_guard          # Userspace loader"
echo "  └── run_guard.sh             # One-click: sudo ./run_guard.sh"
