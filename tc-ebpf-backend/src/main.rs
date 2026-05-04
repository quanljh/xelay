mod cli;
mod config;
mod dataplane;
mod interface;
mod model;
mod reconcile;
mod state;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use config::Config;
use dataplane::AyaDataplane;
use reconcile::Reconciler;

fn main() {
    if let Err(error) = run_cli() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli::resolve_config_path(cli.config)?;
    let mut config = Config::load(&config_path)?;
    if let Some(path) = cli.bpf_object {
        config.bpf_object_path = path;
    }

    let auto_requires_monitoring = config.requires_monitoring();
    let mut logger = Logger::new(config.log_path.clone());
    let dataplane = AyaDataplane::new(config.bpf_object_path.clone());
    let mut reconciler = Reconciler::new(config, dataplane);

    let result = match cli.command {
        Some(Commands::Apply) => {
            logger.log_line("tc-ebpf apply started")?;
            reconciler.apply()?;
            logger.log_line("tc-ebpf apply completed")
        }
        Some(Commands::Run) => run_with_logger(&mut reconciler, &mut logger),
        Some(Commands::Status) => {
            let status = reconciler.status()?;
            let output = cli::render_status(&status);
            print!("{output}");
            logger.log(&output)
        }
        Some(Commands::Check) => {
            let report = reconciler.check()?;
            let output = cli::render_check_report(&report);
            print!("{output}");
            logger.log(&output)
        }
        Some(Commands::Clean) => {
            logger.log_line("tc-ebpf clean started")?;
            reconciler.clean()?;
            logger.log_line("tc-ebpf clean completed")
        }
        None if auto_requires_monitoring => {
            logger.log_line("auto mode selected run")?;
            run_with_logger(&mut reconciler, &mut logger)
        }
        None => {
            logger.log_line("auto mode selected apply")?;
            reconciler.apply()?;
            logger.log_line("tc-ebpf apply completed")
        }
    };

    if let Err(error) = result {
        let _ = logger.log_line(&format!("error: {error:#}"));
        return Err(error);
    }

    Ok(())
}

fn run_with_logger<D: dataplane::Dataplane>(
    reconciler: &mut Reconciler<D>,
    logger: &mut Logger,
) -> Result<()> {
    logger.log_line("tc-ebpf run started")?;
    if logger.is_enabled() {
        reconciler.run_with_log(|| logger.log_line("reconciliation pass completed"))
    } else {
        reconciler.run()
    }
}

struct Logger {
    path: Option<PathBuf>,
}

impl Logger {
    fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }

    fn log_line(&mut self, message: &str) -> Result<()> {
        self.log(&format!("{message}\n"))
    }

    fn log(&mut self, message: &str) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        append_log(path, message)
    }

    fn is_enabled(&self) -> bool {
        self.path.is_some()
    }
}

fn append_log(path: &Path, message: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create log directory {}", parent.display()))?;
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open log file {}", path.display()))?;
    file.write_all(message.as_bytes())
        .with_context(|| format!("failed to write log file {}", path.display()))
}
