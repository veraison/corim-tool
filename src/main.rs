// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};
use log::{debug, error, info};

mod compile;
mod parse;
mod result;
mod util;
mod verify;

use crate::result::{ExitCode, Result};

/// CoRIM tool is a command line utility for working with Concise Reference Integerity Manifests.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// The path into which the command output will be written. If not specified, STDOUT will be
    /// used.
    #[arg(short, long, global = true)]
    output: Option<String>,

    /// The path to JSON representation of CoRIM meta map which will be read (on compile) or
    /// written to (on parse). If not specified on compile, a minimal meta will be generated
    /// instead.
    #[arg(short, long, global = true)]
    meta: Option<String>,

    /// Force overwrite output if exists.
    #[arg(short, long, default_value_t = false, global = true)]
    force: bool,

    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Compile a JSON document into a CBOR CoRIM.
    Compile {
        /// Path to the JSON document to be compiled.
        source: String,

        /// Key used to sign the CoRIM. (CoRIM will be unsigned if the key is not specified.)
        #[arg(short, long)]
        key: Option<String>,

        /// Value for the kid (Key ID) COSE header. This is used to uniquely identify the signing
        /// key, and may be used by the verifier to retrieve the verification key. If not
        /// specified, the file name of the key will be used. This option has no effect if a key is
        /// not specified (and therefore the generated CoRIM is unsigned).
        #[arg(short, long)]
        kid: Option<String>,
    },

    /// Parse a CBOR CoRIM into a JSON document.
    Parse {
        /// Path to the CoRIM to be parased.
        source: String,

        /// Pretty print (indent) the output.
        #[arg(short, long, default_value_t = false)]
        pretty: bool,
    },

    /// Verify signature on a signed CoRIM
    Verify {
        /// Path to the CoRIM to be verified.
        source: String,

        /// Path to the key to be used in verification.
        key: String,
    },
}

fn terminate(res: Result<()>) {
    match &res {
        Ok(()) => {
            info!("done.");
        }
        Err(e) => {
            error!("{e}");
        }
    }

    std::process::exit(res.exit_code());
}

fn main() {
    let args = Cli::parse();
    env_logger::builder()
        .filter_level(args.verbosity.log_level_filter())
        .init();

    let output = match &args.output {
        Some(val) => val,
        None => "<STDOUT>",
    };

    match &args.command {
        Some(Commands::Compile { source, key, kid }) => {
            info!("compiling...");
            debug!(source:?, output:?, key:?; "args:");
            terminate(compile::compile(
                source,
                key,
                kid,
                args.output,
                args.meta,
                args.force,
            ));
        }
        Some(Commands::Parse { source, pretty }) => {
            info!("parsing...");
            debug!(source:?, output:?, pretty:?; "args:");
            terminate(parse::parse(
                source,
                args.output,
                args.meta,
                *pretty,
                args.force,
            ));
        }
        Some(Commands::Verify { source, key }) => {
            info!("verifying...");
            debug!(source:?, key:?; "args:");
            terminate(verify::verify(source, key));
        }
        None => {
            error!("Please specify a command. Use -h/--help for help.");
            std::process::exit(1);
        }
    }

    info!("done.");
}
