#[cfg(target_os = "linux")]
mod inner {
    use std::path::PathBuf;

    use anyhow::{Context, Result};
    use aya::programs::KProbe;
    use log::info;

    pub fn run() -> Result<()> {
        env_logger::init();

        let ebpf_path = PathBuf::from(
            std::env::var("GUARD_BPF_OBJ").unwrap_or_else(|_| {
                "/opt/copy_fail_guard/copy_fail_guard_kprobe.bpf.o".to_string()
            }),
        );

        info!("copy_fail_guard_kprobe: loading eBPF program from {}", ebpf_path.display());

        let mut ebpf = aya::Ebpf::load_file(&ebpf_path)
            .with_context(|| format!("failed to load eBPF object from {}", ebpf_path.display()))?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            log::warn!("failed to init eBPF logger: {e}");
        }

        let program: &mut KProbe = ebpf
            .program_mut("block_af_alg_kprobe")
            .context("eBPF program 'block_af_alg_kprobe' not found")?
            .try_into()?;
        program.load()?;
        program.attach("__sys_socket", 0)?;

        info!("copy_fail_guard_kprobe: attached to __sys_socket (CVE-2026-31431 mitigation active)");
        info!("copy_fail_guard_kprobe: processes creating AF_ALG sockets will be killed (SIGKILL)");
        info!("copy_fail_guard_kprobe: press Ctrl-C to detach and exit");

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(tokio::signal::ctrl_c())?;

        info!("copy_fail_guard_kprobe: detaching, AF_ALG protection removed");
        Ok(())
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = inner::run() {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("error: copy_fail_guard_kprobe requires Linux");
        std::process::exit(1);
    }
}
