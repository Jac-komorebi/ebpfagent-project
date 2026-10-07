use anyhow::{bail, Context, Result};
use std::process::Command;

fn main() -> Result<()> {
    let action = std::env::args().nth(1).unwrap_or_else(|| "run".to_string());

    // xtask 是 workspace 内的构建入口，用 `cargo run -p xtask -- <cmd>` 调用。
    match action.as_str() {
        "build-ebpf" => build_ebpf(),
        "build-user" => build_user(),
        "build" => {
            build_ebpf()?;
            build_user()
        }
        "run" => {
            build_ebpf()?;
            build_user()?;
            run_user()
        }
        other => bail!("unknown xtask command: {other}"),
    }
}

fn build_ebpf() -> Result<()> {
    // eBPF 目标使用 nightly 和 build-std=core，不能用普通 host target 构建。
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "-p",
            "zhy-ebpf",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .status()
        .context("failed to build eBPF")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    Ok(())
}

fn build_user() -> Result<()> {
    // collector 是普通 Linux 用户态程序，输出到 target/release/zhy-collector。
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "zhy-collector"])
        .status()
        .context("failed to build user program")?;

    if !status.success() {
        bail!("user build failed");
    }

    Ok(())
}

fn run_user() -> Result<()> {
    // 加载 eBPF 需要权限；这里直接用 sudo 启动 collector 并传入 eBPF 对象路径。
    let status = Command::new("sudo")
        .env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()))
        .args([
            "-E",
            "target/release/zhy-collector",
            "target/bpfel-unknown-none/release/zhy-ebpf",
        ])
        .status()
        .context("failed to run zhy-collector")?;

    if !status.success() {
        bail!("zhy-collector exited with error");
    }

    Ok(())
}
