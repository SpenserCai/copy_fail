# Copy Fail — CVE-2026-31431

CVE-2026-31431 (Copy Fail) is a local privilege escalation vulnerability in the Linux kernel's `algif_aead` module (AF_ALG subsystem). A logic flaw introduced in August 2017 allows any unprivileged local user to write 4 controlled bytes into the page cache of any readable file via `AF_ALG` + `splice()`, then execute a corrupted setuid binary to gain root. The exploit is deterministic — no race conditions, no kernel offsets, no system crash. It affects all major Linux distributions shipping kernels from 4.14 through 7.0-rc.

CVSS: 7.8 | Fixed in: kernel 7.0, 6.19.12, 6.18.22 | Mainline fix: commit `a664bf3d603d`

Sources: [copy.fail](https://copy.fail), [The Hacker News](https://thehackernews.com/2026/04/new-linux-copy-fail-vulnerability.html), [CloudLinux advisory](https://blog.cloudlinux.com/cve-2026-31431-copy-fail-kernel-update)

## Project structure

```
crates/
├── exp/                        # Exploit PoC (Rust reimplementation)
├── copy_fail_guard/            # Userspace eBPF loader (defense tool)
└── copy_fail_guard-ebpf/       # eBPF LSM program (kernel-side, not in workspace)
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

## crates/copy_fail_guard — eBPF LSM defense tool

A runtime kernel defense that blocks CVE-2026-31431 **without upgrading the kernel**. It uses eBPF LSM (Linux Security Modules) to hook `socket_create` and deny `AF_ALG` socket creation from userspace, cutting off the exploit's first step.

### How it works

```
┌──────────────────────────────────────────┐
│  Userspace loader  (copy_fail_guard)     │
│  • Loads the eBPF object file            │
│  • Attaches to LSM hook                  │
│  • Runs until Ctrl-C (then detaches)     │
└──────────────┬───────────────────────────┘
               │ attach
┌──────────────▼───────────────────────────┐
│  eBPF LSM program  (block_af_alg)        │
│  Hook: socket_create(family, type,       │
│                      protocol, kern)     │
│  Logic:                                  │
│    if family == 38 (AF_ALG)              │
│       && kern == 0 (userspace caller)    │
│    → return -EPERM (deny)                │
│    else → return 0 (allow)               │
└──────────────────────────────────────────┘
```

The exploit chain requires creating an `AF_ALG` socket as the very first step. Blocking this at the LSM level makes the entire attack impossible.

### Why this approach

| Approach | Pros | Cons |
|---|---|---|
| **Upgrade kernel** | Complete fix | Requires reboot; LTS/embedded update cycles are slow; may regress |
| **Blacklist algif_aead module** | Simple | Doesn't work if module is built-in; requires reboot for initcall blacklist |
| **seccomp filter** | Per-process | Must be applied to every process; doesn't protect existing processes |
| **eBPF LSM (this tool)** | System-wide, hot-loadable, no reboot, no kernel rebuild | Requires kernel ≥ 5.7 with `lsm=bpf` enabled |

### Impact on the system

Blocking `AF_ALG` has **near-zero impact** on typical systems:

- **Not affected**: dm-crypt/LUKS, kTLS, IPsec/XFRM, OpenSSL/GnuTLS/NSS (default builds), SSH, kernel keyring crypto — these use the in-kernel crypto API directly, not through `AF_ALG`
- **Potentially affected**: applications explicitly configured to use `AF_ALG` (e.g. OpenSSL with the `afalg` engine enabled, some embedded crypto offload paths)
- **Performance**: zero overhead for anything not calling `socket(AF_ALG, ...)`. The LSM hook check is a single integer comparison

### Prerequisites

1. **Linux kernel ≥ 5.7** (BPF LSM support)
2. **BPF LSM enabled** — verify with:
   ```bash
   cat /sys/kernel/security/lsm
   # Output should contain "bpf", e.g.: capability,lockdown,yama,bpf
   ```
   If `bpf` is missing, add it to kernel boot parameters:
   ```bash
   # Edit /etc/default/grub:
   GRUB_CMDLINE_LINUX="lsm=lockdown,yama,bpf"
   # Then:
   sudo update-grub && sudo reboot
   ```
3. **Root privileges** to load the eBPF program
4. **bpf-linker** to compile the eBPF crate (install with `cargo install bpf-linker`)

### Building

The eBPF program and userspace loader are built separately.

**Step 1: Compile the eBPF program** (must be done on Linux):

```bash
cd crates/copy_fail_guard-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
```

The output is at `target/bpfel-unknown-none/release/copy_fail_guard`.

**Step 2: Build the userspace loader**:

```bash
cargo build --release -p copy_fail_guard
```

### Running

```bash
# Point the loader to the compiled eBPF object and run as root
sudo GUARD_BPF_OBJ=crates/copy_fail_guard-ebpf/target/bpfel-unknown-none/release/copy_fail_guard \
     RUST_LOG=info \
     ./target/release/copy_fail_guard
```

Once running, any attempt to create an `AF_ALG` socket from userspace will be denied with `EPERM`. The exploit PoC will fail at its first step.

Press `Ctrl-C` to detach the eBPF program and restore normal behavior.

### Verifying the defense

With `copy_fail_guard` running in one terminal:

```bash
# In another terminal, try the exploit:
./target/release/copy_fail
# Expected: "error: Operation not permitted" (socket creation blocked)

# Or test directly with Python:
python3 -c "import socket; socket.socket(38, 5, 0)"
# Expected: PermissionError: [Errno 1] Operation not permitted
```

### Current limitations

- **No whitelist support yet** — the current version blocks ALL userspace `AF_ALG` socket creation unconditionally. There is no mechanism to exempt specific processes by PID, cgroup, or command name. This is planned for a future version (via eBPF HashMap maps). For the vast majority of systems this is fine since almost nothing uses `AF_ALG`.
- The eBPF crate must be compiled separately on Linux with `bpf-linker` (it targets `bpfel-unknown-none` and cannot be a normal workspace member).
- Protection is active only while the loader process is running. For persistent protection, run it as a systemd service.

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
