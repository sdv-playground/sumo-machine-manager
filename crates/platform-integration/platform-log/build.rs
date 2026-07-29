// Link libsystemd for the native sd_journal reader — ONLY on Linux. The agent
// also cross-compiles to QNX (where the journal doesn't exist and the source is
// /dev/shmem + /var/log files), so the link must be gated: no libsystemd on nto.
//
// We link the runtime soname directly (`-l:libsystemd.so.0`) rather than `-lsystemd`
// so a build box needs only the shipped library, not the -dev package's bare
// `libsystemd.so` symlink. sd_journal_* have been in LIBSYSTEMD_209 (very old), so
// any systemd is fine. If a target lacks libsystemd entirely, the runtime dlopen
// isn't used — we hard-link — so such targets must build the file-only path; today
// every Linux guest ships systemd, and QNX is gated out here.
// On QNX the log source is slogger2 (the system-log ring); the reader links
// `libslog2parse` (slog2_open_log / slog2_parse_all). Gated to nto, mirroring how
// score-log-slog2's writer links libslog2 and qnx-devices links its QNX libs.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=QNX_TARGET");
    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("linux") => {
            // Native sd_journal reader — verbatim soname so no -dev symlink needed.
            println!("cargo:rustc-link-lib=dylib:+verbatim=libsystemd.so.0");
        }
        Ok("nto") => {
            // Native slog2 reader. QNX_TARGET is set by qnxsdp-env.sh; libs under
            // {QNX_TARGET}/{arch}/lib. qcc also resolves QNX system libs, but be
            // explicit for a plain cargo cross-build.
            if let Ok(qnx_target) = std::env::var("QNX_TARGET") {
                let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
                    Ok("aarch64") => "aarch64le",
                    Ok("x86_64") => "x86_64",
                    Ok("arm") => "armle-v7",
                    _ => "aarch64le",
                };
                println!("cargo:rustc-link-search=native={qnx_target}/{arch}/lib");
            }
            println!("cargo:rustc-link-lib=slog2parse");
        }
        _ => {}
    }
}
