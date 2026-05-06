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
        #[arg(short = 'K', long)]
        kid: Option<String>,

        /// The path to a certificate to be included in x5chain. This flag may be specified multple
        /// times. The certificates will be included in the order they are specified. The first
        /// certificate should contain the public key that should be used to verify the CoRIM; the next
        /// certificate should be the one certifying the signing cert, and so on.
        #[arg(short, long = "cert", num_args(1..))]
        certs: Vec<String>,
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
        #[arg(short, long)]
        key: Option<String>,

        /// Path to a X.509 certificate that will be used as a trusted root during x5chain
        /// validation, in addition to the system certificates. This flag may be specified multiple
        /// times.
        #[arg(short, long = "root", num_args(1..))]
        roots: Vec<String>,
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
        Some(Commands::Compile {
            source,
            key,
            kid,
            certs: cert,
        }) => {
            info!("compiling...");
            debug!(source:?, output:?, key:?; "args:");
            terminate(compile::compile(
                source,
                key,
                kid,
                cert,
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
        Some(Commands::Verify { source, key, roots }) => {
            info!("verifying...");
            debug!(source:?, key:?; "args:");
            terminate(verify::verify(source, key, roots));
        }
        None => {
            error!("Please specify a command. Use -h/--help for help.");
            std::process::exit(1);
        }
    }

    info!("done.");
}
