use clap::{ColorChoice, Parser, Subcommand};
use fuin_controller::types::{FuinPublicKey, FuinSealedSecret, FuinSealedSecretSpec};
use fuin_core::encryption;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams},
    runtime::events::{Event, EventType, Recorder},
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("Kubernetes API error: {0}")]
    Kubernetes(#[from] kube::Error),
    #[error("encryption error: {0}")]
    Encryption(#[from] encryption::Error),
    #[error("input error: {0}")]
    Input(String),
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
    #[arg(short, long)]
    namespace: Option<String>,

    /// Name of the source Kubernetes Secret in the current kube context.
    #[arg(conflicts_with = "from_file")]
    secret: Option<String>,

    /// Path to a Kubernetes Secret YAML file.
    #[arg(long = "from-file", conflicts_with = "secret")]
    from_file: Option<PathBuf>,

    /// Name of the cluster-scoped FuinPublicKey.
    #[arg(long, default_value = "fuin-controller")]
    public_key: String,

    /// Write the generated FuinSealedSecret to a file instead of stdout.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Apply the generated FuinSealedSecret to the current kube context.
    #[arg(long)]
    apply: bool,
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
    let (namespace, source) = match (&args.secret, &args.from_file) {
        (Some(name), None) => {
            let namespace = args.namespace.as_deref().unwrap_or("default");
            let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
            (namespace.to_owned(), secrets.get(name).await?)
        }
        (None, Some(path)) => {
            let content = std::fs::read_to_string(path).map_err(|error| {
                Error::Input(format!("failed to read {}: {error}", path.display()))
            })?;
            let source: Secret = serde_yaml_ng::from_str(&content).map_err(|error| {
                Error::Input(format!("failed to parse {}: {error}", path.display()))
            })?;
            let namespace = args
                .namespace
                .clone()
                .or_else(|| source.metadata.namespace.clone())
                .unwrap_or_else(|| "default".into());
            (namespace, source)
        }
        _ => {
            return Err(Error::Input(
                "provide either a Secret name or --from-file".into(),
            ));
        }
    };
    let source_name = source.name_any();
    let public_keys: Api<FuinPublicKey> = Api::all(client.clone());
    let public_key = public_keys.get(&args.public_key).await?;

    let mut plaintext_data = source
        .data
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| (name, value.0))
        .collect::<BTreeMap<_, _>>();
    if let Some(string_data) = source.string_data {
        for (name, value) in string_data {
            plaintext_data.insert(name, value.into_bytes());
        }
    }
    let source_data = plaintext_data
        .into_iter()
        .map(|(name, value)| {
            encryption::encrypt(&public_key.spec.public_key, value)
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

    let yaml = serde_yaml_ng::to_string(&sealed_secret)
        .map_err(|error| Error::Input(format!("failed to serialize sealed secret: {error}")))?;
    if let Some(path) = &args.output {
        std::fs::write(path, &yaml).map_err(|error| {
            Error::Input(format!("failed to write {}: {error}", path.display()))
        })?;
        if !args.apply {
            eprintln!("wrote {}", path.display());
        }
    } else if !args.apply {
        print!("{yaml}");
    }

    if !args.apply {
        return Ok(());
    }

    let object_ref = sealed_secret.object_ref(&());
    let sealed_secrets: Api<FuinSealedSecret> = Api::namespaced(client.clone(), &namespace);
    sealed_secrets
        .patch(
            &source_name,
            &PatchParams::apply("fuin-cli").force(),
            &Patch::Apply(sealed_secret),
        )
        .await?;
    Recorder::new(client, "fuin-cli".into())
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "SecretSealed".into(),
                note: Some("Encrypted Secret data and applied FuinSealedSecret".into()),
                action: "Seal".into(),
                secondary: None,
            },
            &object_ref,
        )
        .await?;
    println!(
        "sealed Secret `{}` in namespace `{}`",
        source_name, namespace
    );
    Ok(())
}
