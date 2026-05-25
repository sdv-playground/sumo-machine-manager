//! ca-bundle-build — build read-only CA-bundle images.
//!
//! Usage:
//!   ca-bundle-build --input <dir> --output <path> [--format sqfs|qnx6]
//!                   [--tool <path-to-mksquashfs-or-mkqnx6fsimg>]
//!
//! Without `--format`, the format is inferred from the output file
//! extension (`.sqfs` → squashfs, `.qnx6` → qnx6).

use std::path::PathBuf;
use std::process::ExitCode;

use ca_bundle_build::{BuildError, CaBundleImageBuilder, ImageFormat};

const USAGE: &str = "\
Usage: ca-bundle-build --input <dir> --output <path> [options]

Required:
  --input <dir>         Source directory tree to image. For Linux
                        guests this is typically a mirror of
                        /etc/pki/ca-trust/extracted/; for QNX guests
                        a single concatenated PEM at any path.
  --output <path>       Output image path. Format inferred from
                        extension (.sqfs / .qnx6) unless --format
                        is set explicitly.

Options:
  --format sqfs|qnx6    Override format selection from --output's
                        extension.
  --tool <path>         Absolute path to mksquashfs (sqfs) or
                        mkqnx6fsimg (qnx6). Default: $PATH lookup.
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut format: Option<ImageFormat> = None;
    let mut tool: Option<PathBuf> = None;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--input" if i + 1 < argv.len() => {
                input = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
            }
            "--output" if i + 1 < argv.len() => {
                output = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
            }
            "--format" if i + 1 < argv.len() => {
                format = match argv[i + 1].as_str() {
                    "sqfs" | "squashfs" => Some(ImageFormat::Squashfs),
                    "qnx6" => Some(ImageFormat::Qnx6),
                    other => {
                        eprintln!("ca-bundle-build: unknown --format {other:?}");
                        eprintln!("{USAGE}");
                        return ExitCode::from(2);
                    }
                };
                i += 2;
            }
            "--tool" if i + 1 < argv.len() => {
                tool = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("ca-bundle-build: unknown argument {other:?}");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    let input = match input {
        Some(p) => p,
        None => {
            eprintln!("ca-bundle-build: --input is required");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let output = match output {
        Some(p) => p,
        None => {
            eprintln!("ca-bundle-build: --output is required");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let format = match format {
        Some(f) => f,
        None => match output
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
        {
            "sqfs" | "squashfs" => ImageFormat::Squashfs,
            "qnx6" => ImageFormat::Qnx6,
            other => {
                eprintln!(
                    "ca-bundle-build: cannot infer format from extension {other:?}; \
                     pass --format sqfs|qnx6 explicitly"
                );
                return ExitCode::from(2);
            }
        },
    };

    let mut builder = CaBundleImageBuilder::new(&input, format);
    if let Some(t) = tool {
        builder = builder.with_tool_path(t);
    }

    match builder.build(&output) {
        Ok(()) => {
            eprintln!(
                "ca-bundle-build: wrote {} ({:?})",
                output.display(),
                format
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ca-bundle-build: {e}");
            match e {
                BuildError::ToolSpawn { .. } | BuildError::ToolFailed { .. } => {
                    ExitCode::from(3)
                }
                _ => ExitCode::from(1),
            }
        }
    }
}
