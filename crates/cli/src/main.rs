use clap::{ColorChoice, Parser, Subcommand};
use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use fuin_controller::types::{
    FuinClusterSealedSecret, FuinClusterSealedSecretSpec, FuinPublicKey, FuinSealedSecret,
    FuinSealedSecretSpec, NamespaceSelector, SecretTemplate,
};
use fuin_core::encryption;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams},
    runtime::events::{Event, EventType, Recorder},
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

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

    /// Create a cluster-scoped FuinClusterSealedSecret.
    #[arg(long)]
    cluster_wide: bool,

    /// Include namespaces matching a label, for example team=platform. Repeatable.
    #[arg(long = "namespace-label")]
    namespace_labels: Vec<String>,

    /// Exclude a namespace from cluster-wide propagation. Repeatable.
    #[arg(long = "exclude-namespace")]
    exclude_namespaces: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    match cli.command {
        Command::Seal(args) => seal(args).await,
    }
}

async fn seal(args: SealArgs) -> Result<()> {
    let client = Client::try_default().await?;
    let (namespace, source) = match (&args.secret, &args.from_file) {
        (Some(name), None) => {
            let namespace = args.namespace.as_deref().unwrap_or("default");
            let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
            (namespace.to_owned(), secrets.get(name).await?)
        }
        (None, Some(path)) => {
            let content = std::fs::read_to_string(path)
                .wrap_err_with(|| format!("failed to read {}", path.display()))?;
            let source: Secret = serde_yaml_ng::from_str(&content)
                .wrap_err_with(|| format!("failed to parse {}", path.display()))?;
            let namespace = args
                .namespace
                .clone()
                .or_else(|| source.metadata.namespace.clone())
                .unwrap_or_else(|| "default".into());
            (namespace, source)
        }
        _ => {
            bail!("provide either a Secret name or --from-file");
        }
    };
    let source_name = source.name_any();
    let mut template_metadata = BTreeMap::new();
    template_metadata.insert("name".into(), Value::String(source_name.clone()));
    if let Some(labels) = &source.metadata.labels {
        template_metadata.insert("labels".into(), serde_json::to_value(labels)?);
    }
    if let Some(annotations) = &source.metadata.annotations {
        template_metadata.insert("annotations".into(), serde_json::to_value(annotations)?);
    }
    let template = SecretTemplate {
        metadata: Some(template_metadata),
        r#type: source.type_.clone(),
        immutable: source.immutable,
    };
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
        bail!("the Kubernetes Secret `{source_name}` has no data entries");
    }

    if args.cluster_wide {
        let namespace_selector = NamespaceSelector {
            match_labels: parse_labels(&args.namespace_labels)?,
        };
        let sealed_secret = FuinClusterSealedSecret::new(
            &source_name,
            FuinClusterSealedSecretSpec {
                encrypted_data: source_data,
                namespace_selector,
                exclude_namespaces: args.exclude_namespaces.clone(),
                template: Some(template),
            },
        );
        return output_or_apply_cluster(client, &args, &source_name, sealed_secret).await;
    }

    let mut sealed_secret = FuinSealedSecret::new(
        &source_name,
        FuinSealedSecretSpec {
            encrypted_data: source_data,
            template: Some(template),
        },
    );
    sealed_secret.metadata.namespace = Some(namespace.clone());
    output_or_apply_namespaced(client, &args, &source_name, namespace, sealed_secret).await
}

fn parse_labels(labels: &[String]) -> Result<BTreeMap<String, String>> {
    labels
        .iter()
        .map(|label| {
            let (key, value) = label
                .split_once('=')
                .ok_or_else(|| eyre!("label must use key=value: {label}"))?;
            if key.is_empty() || value.is_empty() {
                bail!("label must use key=value: {label}");
            }
            Ok((key.to_owned(), value.to_owned()))
        })
        .collect()
}

async fn output_or_apply_namespaced(
    client: kube::Client,
    args: &SealArgs,
    source_name: &str,
    namespace: String,
    sealed_secret: FuinSealedSecret,
) -> Result<()> {
    let yaml =
        serde_yaml_ng::to_string(&sealed_secret).wrap_err("failed to serialize sealed secret")?;
    if let Some(path) = &args.output {
        std::fs::write(path, &yaml)
            .wrap_err_with(|| format!("failed to write {}", path.display()))?;
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

async fn output_or_apply_cluster(
    client: kube::Client,
    args: &SealArgs,
    source_name: &str,
    sealed_secret: FuinClusterSealedSecret,
) -> Result<()> {
    let yaml =
        serde_yaml_ng::to_string(&sealed_secret).wrap_err("failed to serialize sealed secret")?;
    if let Some(path) = &args.output {
        std::fs::write(path, &yaml)
            .wrap_err_with(|| format!("failed to write {}", path.display()))?;
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
    let sealed_secrets: Api<FuinClusterSealedSecret> = Api::all(client.clone());
    sealed_secrets
        .patch(
            source_name,
            &PatchParams::apply("fuin-cli").force(),
            &Patch::Apply(sealed_secret),
        )
        .await?;
    Recorder::new(client, "fuin-cli".into())
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "ClusterSecretSealed".into(),
                note: Some("Encrypted Secret data and applied FuinClusterSealedSecret".into()),
                action: "Seal".into(),
                secondary: None,
            },
            &object_ref,
        )
        .await?;
    println!("sealed cluster-wide Secret `{source_name}`");
    Ok(())
}
