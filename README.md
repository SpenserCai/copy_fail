# Copy Fail — CVE-2026-31431

CVE-2026-31431 (Copy Fail) is a local privilege escalation vulnerability in the Linux kernel's `algif_aead` module (AF_ALG subsystem). A logic flaw introduced in August 2017 allows any unprivileged local user to write 4 controlled bytes into the page cache of any readable file via `AF_ALG` + `splice()`, then execute a corrupted setuid binary to gain root. The exploit is deterministic — no race conditions, no kernel offsets, no system crash. It affects all major Linux distributions shipping kernels from 4.14 through 7.0-rc.

CVSS: 7.8 | Fixed in: kernel 7.0, 6.19.12, 6.18.22 | Mainline fix: commit `a664bf3d603d`

Sources: [copy.fail](https://copy.fail), [The Hacker News](https://thehackernews.com/2026/04/new-linux-copy-fail-vulnerability.html), [CloudLinux advisory](https://blog.cloudlinux.com/cve-2026-31431-copy-fail-kernel-update)

## This project

This is a Rust reimplementation of the public 732-byte Python PoC. It targets `/usr/bin/su`, splices its page-cache pages into an AF_ALG AEAD socket, and overwrites them with a compressed shell payload. On a vulnerable kernel, running the binary as an unprivileged user produces a root shell.

## Building

Requires Rust 1.85+ (edition 2024).

```bash
cargo build --release
```

The binary is Linux-only. On other platforms it exits with an `Unsupported` error.

## Verifying the vulnerability

> **Warning**: This exploits a real kernel flaw. Only run on systems you own and control, ideally a disposable VM.

1. Boot a VM running a vulnerable kernel (any mainstream distro with kernel < 7.0 / < 6.19.12 / < 6.18.22).

2. Copy the built binary into the VM and run it as a non-root user:

   ```bash
   ./target/release/copy_fail
   ```

3. **Vulnerable**: a root shell (`#`) appears. Run `whoami` to confirm `root`.

4. **Not vulnerable** (patched kernel): the AF_ALG operation fails or the `su` binary behaves normally. You'll see an error or a regular `su` password prompt.

## Verifying the fix

After patching the kernel:

```bash
# Confirm kernel version is at or above the fix
uname -r

# Re-run the tool — it should no longer produce a root shell
./target/release/copy_fail
```

Alternatively, confirm the vulnerable module is neutralized:

```bash
# Check if algif_aead is built-in or a loadable module
modinfo algif_aead | grep filename

# If built-in, blacklist the initcall (requires reboot)
sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
sudo reboot
```
