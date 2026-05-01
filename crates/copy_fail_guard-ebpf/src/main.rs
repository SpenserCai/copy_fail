#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;

/// LSM hook: block AF_ALG socket creation from userspace.
///
/// `socket_create(int family, int type, int protocol, int kern)`
///   - family == 38 (AF_ALG) && kern == 0 → deny
#[lsm(hook = "socket_create")]
pub fn block_af_alg(ctx: LsmContext) -> i32 {
    match try_block_af_alg(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // on error, allow (fail-open)
    }
}

fn try_block_af_alg(ctx: &LsmContext) -> Result<i32, i64> {
    const AF_ALG: i32 = 38;

    let family: i32 = unsafe { ctx.arg(0) };
    let kern: i32 = unsafe { ctx.arg(3) };

    // Only block userspace (kern == 0) AF_ALG socket creation
    if family == AF_ALG && kern == 0 {
        info!(ctx, "copy_fail_guard: blocked AF_ALG socket creation (CVE-2026-31431)");
        return Ok(-1); // -EPERM
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
