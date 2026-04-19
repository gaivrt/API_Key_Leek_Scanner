use anyhow::Result;
use clap::{Parser, Subcommand};

mod github;
mod issue;
mod ratelimit;
mod redact;
mod rules;
mod scan;
mod state;

#[derive(Parser)]
#[command(name = "leak-scanner", version, about = "Multi-vendor GitHub API-key leak scanner")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Search GitHub for leaked keys across all configured vendors
    Scan {
        #[arg(long, default_value = "findings.json")]
        out: String,
        #[arg(long, default_value_t = 1)]
        max_pages: u32,
    },
    /// Open one issue per affected repo (rate-limited, requires --confirm)
    Report {
        #[arg(long)]
        input: String,
        #[arg(long, default_value_t = 5)]
        max: usize,
        #[arg(long, default_value_t = 30)]
        spacing: u64,
        #[arg(long)]
        confirm: bool,
    },
    /// Render per-vendor disclosure-email drafts to a directory
    DraftEmail {
        #[arg(long)]
        input: String,
        #[arg(long, default_value = "disclosure-drafts")]
        out_dir: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("leak_scanner=info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Scan { out, max_pages } => scan::run(&out, max_pages).await,
        Cmd::Report { input, max, spacing, confirm } => {
            issue::run_report(&input, max, spacing, confirm).await
        }
        Cmd::DraftEmail { input, out_dir } => issue::run_draft_email(&input, &out_dir),
    }
}
