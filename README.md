# Copy Fail — CVE-2026-31431

CVE-2026-31431 (Copy Fail) is a local privilege escalation vulnerability in the Linux kernel's `algif_aead` module (AF_ALG subsystem). A logic flaw introduced in August 2017 allows any unprivileged local user to write 4 controlled bytes into the page cache of any readable file via `AF_ALG` + `splice()`, then execute a corrupted setuid binary to gain root. The exploit is deterministic — no race conditions, no kernel offsets, no system crash. It affects all major Linux distributions shipping kernels from 4.14 through 7.0-rc.

CVSS: 7.8 | Fixed in: kernel 7.0, 6.19.12, 6.18.22 | Mainline fix: commit `a664bf3d603d`

Sources: [copy.fail](https://copy.fail), [The Hacker News](https://thehackernews.com/2026/04/new-linux-copy-fail-vulnerability.html), [CloudLinux advisory](https://blog.cloudlinux.com/cve-2026-31431-copy-fail-kernel-update)

## Project structure

```
crates/
├── exp/                            # Exploit PoC (Rust reimplementation)
├── copy_fail_guard/                # Userspace eBPF loader — LSM mode
├── copy_fail_guard-ebpf/           # eBPF LSM program (not in workspace)
├── copy_fail_guard_kprobe/         # Userspace eBPF loader — kprobe mode
└── copy_fail_guard_kprobe-ebpf/    # eBPF kprobe program (not in workspace)
scripts/
└── build_guard.sh                  # One-click build → outputs to dist/
```

## Vulnerability overview

The root cause is a chain of three independent kernel features interacting unsafely:

1. **`AF_ALG` socket** — exposes the kernel crypto API to unprivileged userspace
2. **`splice()`** — zero-copy transfers file data as page cache references (not copies) into the crypto scatterlist
3. **`authencesn` AEAD template** — uses the caller's output buffer as scratch space, writing 4 bytes at `dst[assoclen + cryptlen]`

In 2017, an in-place optimization in `algif_aead.c` (`72548b093ee3`) made `req->src == req->dst`, chaining page cache pages into the writable destination scatterlist. When `authencesn` writes its scratch bytes, it walks past the output buffer into the chained page cache pages. The attacker controls:

- **Which file**: any file readable by the current user
- **Which offset**: determined by splice offset, splice length, and assoclen
- **Which 4 bytes**: comes from AAD bytes 4–7 (seqno_lo), set in sendmsg()

The corrupted page is never marked dirty — the on-disk file is untouched, but `execve()` reads from the page cache. Corrupt a setuid binary → root.

## crates/exp — Exploit PoC

Rust reimplementation of the public 732-byte Python PoC. Targets `/usr/bin/su`, splices its page-cache pages into an AF_ALG AEAD socket, and overwrites them with a compressed shell payload.

### Building

Requires Rust 1.85+ (edition 2024).

```bash
cargo build --release -p copy_fail
```

The binary is Linux-only. On other platforms it exits with an `Unsupported` error.

### Running

> **Warning**: This exploits a real kernel flaw. Only run on systems you own and control, ideally a disposable VM.

1. Boot a VM running a vulnerable kernel (any mainstream distro with kernel < 7.0 / < 6.19.12 / < 6.18.22).

2. Copy the built binary into the VM and run it as a non-root user:

   ```bash
   ./target/release/copy_fail
   ```

3. **Vulnerable**: a root shell (`#`) appears. Run `whoami` to confirm `root`.

4. **Not vulnerable** (patched kernel): the AF_ALG operation fails or the `su` binary behaves normally. You'll see an error or a regular `su` password prompt.

## Defense tool — copy_fail_guard

A runtime kernel defense that blocks CVE-2026-31431 **without upgrading the kernel or rebooting**. It uses eBPF to intercept `AF_ALG` socket creation, cutting off the exploit's first step.

Two modes are provided. The one-click loader auto-selects the best available mode:

| | LSM mode | kprobe mode |
|---|---|---|
| **How it blocks** | Returns `-EPERM` (socket creation denied) | `SIGKILL` (process killed) |
| **Kernel requirement** | ≥ 5.7 with `lsm=bpf` boot parameter | ≥ 5.3, no special parameters |
| **Needs reboot to enable** | Maybe (if `lsm=bpf` not already set) | **No** |
| **Hook point** | `socket_create` LSM hook | `__sys_socket` kprobe |

### How it works

```
┌──────────────────────────────────────────────────┐
│  run_guard.sh                                    │
│  • Detects BPF LSM support                       │
│  • LSM available  → copy_fail_guard (EPERM)      │
│  • LSM unavailable → copy_fail_guard_kprobe (KILL)│
└──────────────┬───────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────┐
│  eBPF program                                    │
│  if socket family == 38 (AF_ALG)                 │
│     → block (EPERM or SIGKILL)                   │
│  else                                            │
│     → allow                                      │
└──────────────────────────────────────────────────┘
```

### Impact on the system

Blocking `AF_ALG` has **near-zero impact** on typical systems:

- **Not affected**: dm-crypt/LUKS, kTLS, IPsec/XFRM, OpenSSL/GnuTLS/NSS (default builds), SSH, kernel keyring crypto — these use the in-kernel crypto API directly, not through `AF_ALG`
- **Potentially affected**: applications explicitly configured to use `AF_ALG` (e.g. OpenSSL with the `afalg` engine enabled, some embedded crypto offload paths)
- **Performance**: zero overhead for anything not calling `socket(AF_ALG, ...)`

### Building

**One-click build** (recommended):

```bash
./scripts/build_guard.sh
```

This automatically installs missing toolchains (nightly, bpf-linker), compiles all eBPF programs and userspace loaders, and outputs everything to `dist/`:

```
dist/
├── copy_fail_guard.bpf.o          # eBPF LSM program
├── copy_fail_guard_kprobe.bpf.o   # eBPF kprobe program
├── copy_fail_guard                 # Userspace loader (LSM)
├── copy_fail_guard_kprobe          # Userspace loader (kprobe)
└── run_guard.sh                    # Auto-select: sudo ./run_guard.sh
```

Copy the `dist/` directory to any target machine and run `sudo ./run_guard.sh` to activate protection.

**Manual build** (step by step):

Step 1: Compile the eBPF programs (must be done on Linux):

```bash
# LSM variant
cd crates/copy_fail_guard-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release

# kprobe variant
cd crates/copy_fail_guard_kprobe-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
```

**Step 2: Build the userspace loaders**:

```bash
cargo build --release -p copy_fail_guard -p copy_fail_guard_kprobe
```

### Running

**Recommended** — auto-selects the best mode:

```bash
sudo ./dist/run_guard.sh
```

**Manual** — run a specific mode:

```bash
# LSM mode (requires lsm=bpf)
sudo GUARD_BPF_OBJ=path/to/copy_fail_guard.bpf.o RUST_LOG=info ./copy_fail_guard

# kprobe mode (works everywhere)
sudo GUARD_BPF_OBJ=path/to/copy_fail_guard_kprobe.bpf.o RUST_LOG=info ./copy_fail_guard_kprobe
```

Press `Ctrl-C` to detach the eBPF program and restore normal behavior.

### Verifying the defense

With the guard running in one terminal:

```bash
# In another terminal, try the exploit:
./target/release/copy_fail
# LSM mode:   "error: Operation not permitted"
# kprobe mode: "已杀死" / "Killed"

# Or test directly with Python:
python3 -c "import socket; socket.socket(38, 5, 0)"
# LSM mode:   PermissionError: [Errno 1] Operation not permitted
# kprobe mode: Killed
```

### Current limitations

- **No whitelist support yet** — the current version blocks ALL userspace `AF_ALG` socket creation unconditionally. There is no mechanism to exempt specific processes by PID, cgroup, or command name. This is planned for a future version (via eBPF HashMap maps). For the vast majority of systems this is fine since almost nothing uses `AF_ALG`.
- The eBPF crates must be compiled separately on Linux with `bpf-linker` (they target `bpfel-unknown-none` and cannot be normal workspace members).
- Protection is active only while the loader process is running. For persistent protection, run it as a systemd service.

### Enabling BPF LSM (optional, for LSM mode)

Most distributions do not enable BPF LSM by default. If you want the cleaner LSM mode (EPERM instead of SIGKILL):

```bash
# Check current LSMs:
cat /sys/kernel/security/lsm

# If "bpf" is missing, add it:
sudo sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=lockdown,capability,yama,apparmor,bpf"/' /etc/default/grub
sudo update-grub && sudo reboot
```

The kprobe mode works without this step.

## Verifying the kernel fix

After patching the kernel to ≥ 7.0 / ≥ 6.19.12 / ≥ 6.18.22:

```bash
# Confirm kernel version
uname -r

# Re-run the exploit — it should no longer produce a root shell
./target/release/copy_fail
```

Alternatively, confirm the vulnerable module is neutralized:

```bash
modinfo algif_aead | grep filename

# If built-in, blacklist the initcall (requires reboot)
sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
sudo reboot
```
