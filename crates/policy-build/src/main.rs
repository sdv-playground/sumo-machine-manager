//! policy-build — build read-only policy images.
//!
//! Usage:
//!   policy-build --input <dir> --output <path> [--format sqfs|qnx6]
//!                [--tool <path-to-mksquashfs-or-mkqnx6fs>]
//!                [--skip-validation]
//!
//! Without `--format`, the format is inferred from the output file
//! extension (`.sqfs` → squashfs, `.qnx6` → qnx6).

use std::path::PathBuf;
use std::process::ExitCode;

use policy_build::{BuildError, ImageFormat, PolicyImageBuilder};

const USAGE: &str = "\
Usage: policy-build --input <dir> --output <path> [options]

Required:
  --input <dir>         Source policy directory. Must contain
                        policy.yaml and roots/. Optional:
                        launcher-policy.yaml, crl.yaml.
  --output <path>       Output image path. Format inferred from
                        extension (.sqfs / .qnx6) unless --format
                        is set explicitly.

Options:
  --format sqfs|qnx6    Override format selection from --output's
                        extension.
  --tool <path>         Absolute path to mksquashfs (sqfs) or
                        mkqnx6fs (qnx6). Default: $PATH lookup.
  --skip-validation     Don't validate the source dir via
                        policy-partition before building. For
                        tests that produce intentionally-broken
                        images; production callers should not
                        use this.
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut format: Option<ImageFormat> = None;
    let mut tool: Option<PathBuf> = None;
    let mut skip_validation = false;

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
                        eprintln!("policy-build: unknown --format {other:?}");
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
            "--skip-validation" => {
                skip_validation = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("policy-build: unknown argument {other:?}");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    let input = match input {
        Some(p) => p,
        None => {
            eprintln!("policy-build: --input is required");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let output = match output {
        Some(p) => p,
        None => {
            eprintln!("policy-build: --output is required");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    // Infer format from extension if not explicit.
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
                    "policy-build: cannot infer format from extension {other:?}; \
                     pass --format sqfs|qnx6 explicitly"
                );
                return ExitCode::from(2);
            }
        },
    };

    let mut builder = PolicyImageBuilder::new(&input, format);
    if let Some(t) = tool {
        builder = builder.with_tool_path(t);
    }
    if skip_validation {
        builder = builder.skip_validation();
    }

    match builder.build(&output) {
        Ok(()) => {
            eprintln!(
                "policy-build: wrote {} ({:?})",
                output.display(),
                format
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("policy-build: {e}");
            // Distinguish "image build tool blew up" (likely environmental)
            // from "source dir is wrong" (likely operator's fault). Both
            // exit non-zero; an operator-facing distinction may be useful
            // for CI scripts.
            match e {
                BuildError::ToolSpawn { .. } | BuildError::ToolFailed { .. } => {
                    ExitCode::from(3)
                }
                _ => ExitCode::from(1),
            }
        }
    }
}
