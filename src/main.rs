use clap::Parser;
use rea::cli::{execute_cli, Cli};
use rea::error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Err(e) = execute_cli(cli).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    Ok(())
}
