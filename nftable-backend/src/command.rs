use std::ffi::OsStr;
use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};

/// Captured stdout from a successfully executed child process.
#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub stdout: String,
}

/// Runs a command with arguments and returns stdout if the process exits successfully.
///
/// Stderr and the exit status are included in the error so callers can surface useful
/// diagnostics for failed `ip`, `nft`, `conntrack`, or `sysctl` calls.
pub fn run<I, S>(program: &str, args: I) -> Result<CmdOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute `{program}`"))?;

    if !output.status.success() {
        bail!(
            "`{program}` failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(CmdOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

/// Runs a command, writes `input` to its stdin, and returns stdout on success.
///
/// This is used for tools like `nft -f -`, where the generated ruleset is streamed
/// directly instead of being written to a temporary file.
pub fn run_input<I, S>(program: &str, args: I, input: &str) -> Result<CmdOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute `{program}`"))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("failed to open stdin for `{program}`"))?;
        stdin.write_all(input.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "`{program}` failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(CmdOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

/// Checks whether a command is available in `PATH`.
///
/// The controller uses this for preflight checks before attempting privileged setup.
pub fn command_exists(program: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program} >/dev/null 2>&1"))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
