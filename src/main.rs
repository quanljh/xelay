mod cli;
mod command;
mod config;
mod conntrack;
mod namespace;
mod nft;
mod reconcile;
mod state;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use config::Config;
use reconcile::Reconciler;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    let mut reconciler = Reconciler::new(config);

    match cli.command {
        Commands::Apply => {
            reconciler.apply()?;
        }
        Commands::Run => {
            reconciler.run()?;
        }
        Commands::Status => {
            let status = reconciler.status()?;
            print!("{}", cli::render_status(&status));
        }
        Commands::Check => {
            let report = reconciler.check()?;
            print!("{}", cli::render_check_report(&report));
        }
    }

    Ok(())
}
