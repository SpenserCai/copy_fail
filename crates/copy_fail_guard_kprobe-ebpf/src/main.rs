#![no_std]
#![no_main]

use aya_ebpf::{helpers::bpf_send_signal, macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

/// Kprobe on __sys_socket: kill any userspace process creating AF_ALG sockets.
///
/// `int __sys_socket(int family, int type, int protocol)`
///
/// No LSM required. Works on kernel ≥ 5.3.
#[kprobe]
pub fn block_af_alg_kprobe(ctx: ProbeContext) -> u32 {
    match try_block(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_block(ctx: &ProbeContext) -> Result<u32, i64> {
    const AF_ALG: u64 = 38;

    let family: u64 = ctx.arg(0).ok_or(1i64)?;

    if family == AF_ALG {
        info!(ctx, "copy_fail_guard: killing process creating AF_ALG socket (CVE-2026-31431)");
        unsafe { bpf_send_signal(9) }; // SIGKILL
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
