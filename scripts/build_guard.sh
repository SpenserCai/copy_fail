#!/usr/bin/env bash
# Build copy_fail_guard (eBPF program + userspace loader)
# Builds BOTH the LSM variant and the kprobe variant.
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

# --- build LSM eBPF program ---
info "Building eBPF LSM program..."
cargo +nightly build \
    --manifest-path "${ROOT}/crates/copy_fail_guard-ebpf/Cargo.toml" \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

# --- build kprobe eBPF program ---
info "Building eBPF kprobe program..."
cargo +nightly build \
    --manifest-path "${ROOT}/crates/copy_fail_guard_kprobe-ebpf/Cargo.toml" \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

# --- build userspace loaders ---
info "Building userspace loaders..."
cargo build --manifest-path "${ROOT}/Cargo.toml" \
    -p copy_fail_guard -p copy_fail_guard_kprobe --release

# --- assemble dist ---
rm -rf "$OUT"
mkdir -p "$OUT"

cp "${ROOT}/crates/copy_fail_guard-ebpf/target/bpfel-unknown-none/release/copy_fail_guard" \
   "$OUT/copy_fail_guard.bpf.o"
cp "${ROOT}/crates/copy_fail_guard_kprobe-ebpf/target/bpfel-unknown-none/release/copy_fail_guard_kprobe" \
   "$OUT/copy_fail_guard_kprobe.bpf.o"
cp "${ROOT}/target/release/copy_fail_guard"        "$OUT/copy_fail_guard"
cp "${ROOT}/target/release/copy_fail_guard_kprobe" "$OUT/copy_fail_guard_kprobe"

# --- generate one-click loader script ---
cat > "$OUT/run_guard.sh" << 'LOADER_SCRIPT'
#!/usr/bin/env bash
# One-click loader for copy_fail_guard (CVE-2026-31431 mitigation)
# Auto-selects LSM mode (preferred) or kprobe mode (fallback).
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
info()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
    red "Error: must run as root"
    echo "Usage: sudo $0"
    exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
    red "Error: Linux required"; exit 1
fi

# Auto-detect: prefer LSM, fallback to kprobe
USE_LSM=false
if [ -f /sys/kernel/security/lsm ] && grep -q 'bpf' /sys/kernel/security/lsm; then
    USE_LSM=true
fi

if [ "$USE_LSM" = true ]; then
    green "BPF LSM detected — using LSM mode (socket creation returns EPERM)"
    exec env GUARD_BPF_OBJ="${DIR}/copy_fail_guard.bpf.o" RUST_LOG=info \
        "${DIR}/copy_fail_guard"
else
    info "BPF LSM not available — using kprobe mode (AF_ALG processes will be killed)"
    exec env GUARD_BPF_OBJ="${DIR}/copy_fail_guard_kprobe.bpf.o" RUST_LOG=info \
        "${DIR}/copy_fail_guard_kprobe"
fi
LOADER_SCRIPT

chmod +x "$OUT/run_guard.sh"

green "Build complete. Output in: $OUT/"
echo ""
echo "  dist/"
echo "  ├── copy_fail_guard.bpf.o          # eBPF LSM program"
echo "  ├── copy_fail_guard_kprobe.bpf.o   # eBPF kprobe program"
echo "  ├── copy_fail_guard                 # Userspace loader (LSM)"
echo "  ├── copy_fail_guard_kprobe          # Userspace loader (kprobe)"
echo "  └── run_guard.sh                    # Auto-select: sudo ./run_guard.sh"
echo ""
echo "  run_guard.sh auto-detects BPF LSM support:"
echo "    • LSM available  → blocks socket creation (EPERM)"
echo "    • LSM unavailable → kills AF_ALG processes (SIGKILL)"
