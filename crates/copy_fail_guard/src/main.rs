#[cfg(target_os = "linux")]
mod inner {
    use std::path::PathBuf;

    use anyhow::{Context, Result};
    use aya::programs::Lsm;
    use aya::Btf;
    use log::info;

    pub fn run() -> Result<()> {
        env_logger::init();

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async { run_async().await })
    }

    async fn run_async() -> Result<()> {
        let ebpf_path = PathBuf::from(
            std::env::var("GUARD_BPF_OBJ").unwrap_or_else(|_| {
                "/opt/copy_fail_guard/copy_fail_guard.bpf.o".to_string()
            }),
        );

        info!("copy_fail_guard: loading eBPF program from {}", ebpf_path.display());

        let mut ebpf = aya::Ebpf::load_file(&ebpf_path)
            .with_context(|| format!("failed to load eBPF object from {}", ebpf_path.display()))?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            log::warn!("failed to init eBPF logger: {e}");
        }

        let btf = Btf::from_sys_fs()?;
        let program: &mut Lsm = ebpf
            .program_mut("block_af_alg")
            .context("eBPF program 'block_af_alg' not found")?
            .try_into()?;
        program.load("socket_create", &btf)?;
        program.attach()?;

        info!("copy_fail_guard: AF_ALG socket creation is now blocked (CVE-2026-31431 mitigation active)");
        info!("copy_fail_guard: press Ctrl-C to detach and exit");

        tokio::signal::ctrl_c().await?;

        info!("copy_fail_guard: detaching, AF_ALG protection removed");
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
        eprintln!("error: copy_fail_guard requires Linux with BPF LSM support");
        std::process::exit(1);
    }
}
