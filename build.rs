use std::env;
use std::io::Error;

fn main() -> Result<(), Error> {
    // Only generate completions when GENERATE_COMPLETIONS is set or during
    // install builds, to avoid slowing down normal development builds.
    if env::var("GENERATE_COMPLETIONS").is_ok() || env::var("PROFILE").as_deref() == Ok("release") {
        generate_completions()?;
    }
    Ok(())
}

fn generate_completions() -> Result<(), Error> {
    use clap::CommandFactory;
    use clap_complete::{generate_to, Shell};

    // We need to define the CLI structure here since build.rs can't
    // import from src/. This must mirror src/main.rs.
    #[derive(clap::Parser)]
    #[command(name = "snag", version, about = "P2P file sharing from your terminal")]
    struct Cli {
        #[command(subcommand)]
        command: Option<Commands>,
    }

    #[derive(clap::Subcommand)]
    enum Commands {
        /// Send files to someone
        #[command(alias = "s")]
        Send {
            paths: Vec<std::path::PathBuf>,
            #[arg(short, long, default_value = "0")]
            port: u16,
            #[arg(long)]
            pipe: bool,
            #[arg(long)]
            bind: Option<String>,
            #[arg(long)]
            no_compress: bool,
            #[arg(long, conflicts_with = "until")]
            timer: Option<String>,
            #[arg(long, conflicts_with = "timer")]
            until: Option<String>,
            #[arg(long)]
            downloads: Option<u32>,
        },
        /// Receive files using a share code
        #[command(alias = "r")]
        Receive {
            code: String,
            #[arg(short, long, default_value = ".")]
            output: std::path::PathBuf,
            #[arg(long)]
            pipe: bool,
            #[arg(long)]
            overwrite: bool,
            #[arg(short, long)]
            yes: bool,
        },
        /// Discover peers sharing files on your local network
        #[command(alias = "d")]
        Discover {
            #[arg(short, long, default_value = "5")]
            timeout: u64,
        },
        /// Show default configuration
        #[command(alias = "cfg")]
        Config,
        /// Start a relay server for NAT traversal
        Relay {
            #[arg(long, default_value = "19816")]
            port: u16,
            #[arg(long, default_value = "1000")]
            max_rooms: usize,
        },
        /// Update snag to the latest version
        #[command(alias = "u")]
        Update {
            #[arg(long)]
            check: bool,
            #[arg(long)]
            force: bool,
        },
    }

    let outdir = std::path::PathBuf::from(
        env::var("OUT_DIR").unwrap_or_else(|_| "target/completions".into()),
    );
    let completions_dir = outdir.join("completions");
    std::fs::create_dir_all(&completions_dir)?;

    let mut cmd = Cli::command();

    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        generate_to(shell, &mut cmd, "snag", &completions_dir)?;
    }

    // Tell cargo where completions were generated
    println!(
        "cargo:warning=Shell completions generated in {}",
        completions_dir.display()
    );

    Ok(())
}
