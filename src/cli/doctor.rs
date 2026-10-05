use crate::providers::list_providers;
use colored::Colorize;

pub fn run_doctor() {
    println!("\n{}", "REA Doctor System Diagnostic".bold().cyan());
    println!("{}", "==================================================".dimmed());
    println!("REA Version:     {}", env!("CARGO_PKG_VERSION").green());
    println!("Operating Sys:   {}", std::env::consts::OS.yellow());
    println!("Host Arch:       {}", std::env::consts::ARCH.yellow());

    println!("\n{}", "Reverse Engineering Providers:".bold());
    for (id, desc, avail) in list_providers() {
        let status_badge = if avail {
            "✓ READY".green().bold()
        } else {
            "✗ NOT FOUND".red()
        };
        println!("  {:<12} [{}] - {}", id.bold(), status_badge, desc);
    }

    println!("\n{}", "Agent Configuration Readiness:".bold());
    let clients = crate::cli::setup::detect_clients();
    for (client, detected, path) in clients {
        let path_str = path.map(|p| p.display().to_string()).unwrap_or_default();
        let badge = if detected {
            "DETECTED".green()
        } else {
            "ABSENT".dimmed()
        };
        println!("  {:<16} [{}] {}", client.display_name.bold(), badge, path_str.dimmed());
    }

    println!("\n{}", "System is ready for agent investigation with REA.".green().bold());
}
