use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use std::path::PathBuf;

mod compression;
mod cpk;
mod endian;
mod error;
mod utf;

use cpk::Cpk;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all files in the CPK archive
    List {
        /// Input CPK file
        input: PathBuf,
    },
    /// Extract a specific file or all files
    Extract {
        /// Input CPK file
        input: PathBuf,
        /// File to extract (or "all" for all files)
        target: String,
    },
    /// Replace a file in the CPK archive
    Replace {
        /// Input CPK file
        input: PathBuf,
        /// File to replace
        target: String,
        /// Replacement file
        replacement: PathBuf,
        /// Output CPK file (optional, defaults to modifying input)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    env_logger::init();

    println!("CriPakTools (Rust Edition)\n");

    let cli = Cli::parse();

    match &cli.command {
        Commands::List { input } => {
            let mut cpk = Cpk::new();
            cpk.read_cpk(input)?;

            for entry in &cpk.file_table {
                if entry.file_type == "FILE" {
                    let full_path = match (&entry.dir_name, &entry.file_name) {
                        (Some(dir), file_name) => format!("{}/{}", dir, file_name),
                        (None, file_name) => file_name.clone(),
                    };
                    println!("{}", full_path);
                }
            }
        }

        Commands::Extract { input, target } => {
            let mut cpk = Cpk::new();
            cpk.read_cpk(input)?;

            if target.to_lowercase() == "all" {
                info!("Extracting all files...");
                cpk.extract_all(input)?;
            } else {
                info!("Extracting: {}", target);
                cpk.extract_file(input, target)?;
            }
        }

        Commands::Replace {
            input,
            target,
            replacement,
            output,
        } => {
            let mut cpk = Cpk::new();
            cpk.read_cpk(input)?;

            let output_path = output.as_ref().unwrap_or(input);
            info!(
                "Replacing {} with {} in {}",
                target,
                replacement.display(),
                output_path.display()
            );
            cpk.replace_file(input, target, replacement, output_path)?;
        }
    }

    Ok(())
}
