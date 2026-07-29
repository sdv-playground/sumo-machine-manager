// Link QNX's libslog2 — ONLY when building for the QNX target (nto). On Linux
// (dev / QEMU container) the crate is a no-op stub with no QNX deps, so this
// build script does nothing there. Mirrors how qnx-devices / vhealth gate their
// QNX linkage (see tasks/host-log-pipeline-design.md, reference_qnx_rust_toolchain).
fn main() {
    println!("cargo:rerun-if-env-changed=QNX_TARGET");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("nto") {
        return;
    }
    // QNX_TARGET is set by qnxsdp-env.sh; libs live under {QNX_TARGET}/{arch}/lib.
    let qnx_target = std::env::var("QNX_TARGET")
        .expect("QNX_TARGET not set — source $QNX_SDP/qnxsdp-env.sh before building for nto");
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "aarch64le",
        Ok("x86_64") => "x86_64",
        Ok("arm") => "armle-v7",
        other => panic!("host-log-slog2: unhandled QNX target arch {other:?}"),
    };
    println!("cargo:rustc-link-search=native={qnx_target}/{arch}/lib");
    // Dynamic link (the SDP ships libslog2.so, no static archive).
    println!("cargo:rustc-link-lib=slog2");
}
