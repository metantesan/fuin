use clap::{ColorChoice, Parser, Subcommand};
use fuin_controller::types::{FuinPublicKey, FuinSealedSecret, FuinSealedSecretSpec};
use fuin_core::encryption;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, ResourceExt,
    api::{Patch, PatchParams},
};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("Kubernetes API error: {0}")]
    Kubernetes(#[from] kube::Error),
    #[error("encryption error: {0}")]
    Encryption(#[from] encryption::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("the Kubernetes Secret `{0}` has no data entries")]
    EmptySecret(String),
}

#[derive(Debug, Parser)]
#[command(name = "fuin", version, color = ColorChoice::Always)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Encrypt a Kubernetes Secret into a FuinSealedSecret.
    Seal(SealArgs),
}

#[derive(Debug, clap::Args)]
struct SealArgs {
    /// Kubernetes namespace containing the source Secret.
    #[arg(short, long, default_value = "default")]
    namespace: String,

    /// Name of the source Kubernetes Secret.
    secret: String,

    /// Name of the cluster-scoped FuinPublicKey.
    #[arg(long, default_value = "fuin-controller")]
    public_key: String,

    /// Print the generated object without applying it.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Seal(args) => seal(args).await,
    }
}

async fn seal(args: SealArgs) -> Result<(), Error> {
    let client = Client::try_default().await?;
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &args.namespace);
    let source = secrets.get(&args.secret).await?;
    let source_name = source.name_any();
    let public_keys: Api<FuinPublicKey> = Api::all(client.clone());
    let public_key = public_keys.get(&args.public_key).await?;

    let source_data = source
        .data
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| {
            encryption::encrypt(&public_key.spec.public_key, value.0)
                .map(|encrypted| (name, encrypted))
        })
        .collect::<Result<BTreeMap<_, _>, encryption::Error>>()?;
    if source_data.is_empty() {
        return Err(Error::EmptySecret(source_name.clone()));
    }

    let sealed_secret = FuinSealedSecret::new(
        &source_name,
        FuinSealedSecretSpec {
            encrypted_data: source_data,
            template: None,
        },
    );

    if args.dry_run {
        println!("{}", serde_json::to_string_pretty(&sealed_secret)?);
        return Ok(());
    }

    let sealed_secrets: Api<FuinSealedSecret> = Api::namespaced(client, &args.namespace);
    sealed_secrets
        .patch(
            &source_name,
            &PatchParams::apply("fuin-cli").force(),
            &Patch::Apply(sealed_secret),
        )
        .await?;
    println!(
        "sealed Secret `{}` in namespace `{}`",
        source_name, args.namespace
    );
    Ok(())
}
