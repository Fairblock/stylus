use clap::{Parser, Subcommand, Args, ValueEnum};

mod check;
mod constants;
mod deploy;

#[derive(Parser, Debug)]
#[command(name = "stylus")]
#[command(author = "Offchain Labs, Inc.")]
#[command(version = "0.0.1")]
#[command(about = "Cargo command for developing Arbitrum Stylus projects", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Instrument a Rust project using Stylus, optionally outputting the brotli-compressed,
    /// compiled WASM code to deploy on-chain. This command runs compiled WASM code through
    /// Stylus instrumentation checks and reports any failures. Allows for disabling specific .
    /// checks via the `--disabled-checks` flag.
    #[command(alias = "c")]
    Check {
        disabled_checks: Option<Vec<String>>,
        output_file: Option<String>,
    },
    /// Instruments a Rust project using Stylus and by outputting its brotli-compressed WASM code.
    /// Then, it submits a single, multicall transaction that both deploys the WASM
    /// program to an address and triggers a compilation onchain by default. This transaction is atomic,
    /// and will revert if either the program creation or onchain compilation step fails.
    /// Developers can choose to split up the deploy and compile steps via this command as desired.
    #[command(alias = "d")]
    Deploy(DeployConfig),
}

#[derive(Debug, Args)]
pub struct DeployConfig {
    /// Does not submit a transaction, but instead estimates the gas required
    /// to complete the operation.
    #[arg(long)]
    estimate_gas: bool,
    /// By default, submits a single, atomic deploy and compile transaction to Arbitrum.
    /// Otherwise, a user could choose to split up the deploy and compile steps into individual transactions.
    #[arg(long, value_enum)]
    mode: Option<DeployMode>,
    /// The endpoint of the L2 node to connect to.
    #[arg(short, long, default_value = "http://localhost:8545")]
    endpoint: String,
    /// Address of a multicall Stylus program on L2 to use for the atomic, onchain deploy+compile
    /// operation. If not provided, address <INSERT_ADDRESS_HERE> will be used.
    #[arg(long)]
    // TODO: Use an alloy primitive address type for this.
    multicall_program_addr: Option<String>,
    /// Wallet source to use with the cargo stylus plugin.
    #[command(flatten)]
    wallet: WalletSource,
} 

#[derive(Debug, Clone, ValueEnum)]
pub enum DeployMode {
    DeployOnly,
    CompileOnly,
}

#[derive(Clone, Debug, Args)]
#[group(required = true, multiple = false)]
pub struct WalletSource {
    #[arg(long, group = "keystore")]
    keystore_path: Option<String>,
    #[arg(long, group = "keystore")]
    keystore_password_path: Option<String>,
    #[arg(long)]
    private_key_path: Option<String>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Check {
            disabled_checks, ..
        } => {
            let disabled = disabled_checks.as_ref().map(|f| {
                f.into_iter()
                    .map(|s| s.as_str().into())
                    .collect::<Vec<check::StylusCheck>>()
            });
            check::run_checks(disabled)
        }
        Commands::Deploy(deploy_config) => {
            deploy::deploy_and_compile_onchain(deploy_config).await
        }
    }
}
