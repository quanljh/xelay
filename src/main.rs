mod cli;
mod command;
mod config;
mod conntrack;
mod namespace;
mod nft;
mod reconcile;
mod state;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use config::Config;
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
    let config = Config::load(&config_path)?;
    let auto_requires_monitoring = config.requires_monitoring();
    let mut logger = Logger::new(config.log_path.clone());
    let mut reconciler = Reconciler::new(config);

    let result = match cli.command {
        Some(Commands::Apply) => {
            logger.log_line("apply started")?;
            reconciler.apply()?;
            logger.log_line("apply completed")
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
        None if auto_requires_monitoring => {
            logger.log_line("auto mode selected run")?;
            run_with_logger(&mut reconciler, &mut logger)
        }
        None => {
            logger.log_line("auto mode selected apply")?;
            reconciler.apply()?;
            logger.log_line("apply completed")
        }
    };

    if let Err(error) = result {
        let _ = logger.log_line(&format!("error: {error:#}"));
        return Err(error);
    }

    Ok(())
}

fn run_with_logger(reconciler: &mut Reconciler, logger: &mut Logger) -> Result<()> {
    logger.log_line("run started")?;
    if logger.is_enabled() {
        reconciler.run_with_log(|| logger.log_line("reconciliation pass completed"))
    } else {
        reconciler.run()
    }
}

/// Append-only file logger configured by `Config::log_path`.
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

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("xelay-{name}-{nonce}.log"))
    }

    #[test]
    fn logger_appends_to_existing_file() {
        let path = temp_path("append");
        fs::write(&path, "existing\n").unwrap();

        let mut logger = Logger::new(Some(path.clone()));
        logger.log("new\n").unwrap();

        let logged = fs::read_to_string(&path).unwrap();
        assert_eq!(logged, "existing\nnew\n");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn logger_creates_parent_directories() {
        let path = temp_path("parent")
            .with_file_name("nested")
            .join("xelay.log");

        let mut logger = Logger::new(Some(path.clone()));
        logger.log_line("created").unwrap();

        let logged = fs::read_to_string(&path).unwrap();
        assert_eq!(logged, "created\n");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(path.parent().unwrap());
    }

    #[test]
    fn logger_is_noop_without_path() {
        let mut logger = Logger::new(None);
        logger.log_line("ignored").unwrap();
    }
}
