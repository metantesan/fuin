use crate::types::{
    FuinPrivateKey, FuinPrivateKeySpec, FuinPublicKey, FuinPublicKeySpec, FuinSealedSecret,
    FuinSealedSecretStatus, SecretPhase,
};
use fuin_core::encryption;
use futures::StreamExt;
use k8s_openapi::{
    ByteString, api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams, PostParams},
    runtime::{Controller, controller::Action, watcher},
};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;
use tokio::time::Duration;
use tracing::{error, info, warn};

const CONTROLLER_NAMESPACE_ENV: &str = "FUIN_CONTROLLER_NAMESPACE";
const PRIVATE_KEY_NAME: &str = "fuin-controller-key";
const PUBLIC_KEY_NAME: &str = "fuin-controller";
const FIELD_MANAGER: &str = "fuin-controller";

#[derive(Debug, Error)]
pub enum Error {
    #[error("Kubernetes API error: {0}")]
    Kubernetes(#[from] kube::Error),
    #[error("age encryption error: {0}")]
    Encryption(#[from] encryption::Error),
    #[error("{0}")]
    Configuration(String),
    #[error("sealed secret has no namespace")]
    MissingNamespace,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Context {
    client: Client,
    private_key: String,
}

pub async fn run() -> Result<()> {
    let client = Client::try_default().await?;
    let controller_namespace = std::env::var(CONTROLLER_NAMESPACE_ENV).map_err(|_| {
        Error::Configuration(format!(
            "{CONTROLLER_NAMESPACE_ENV} must be set to the controller namespace"
        ))
    })?;
    let private_key = ensure_controller_key(&client, &controller_namespace).await?;

    let context = Arc::new(Context {
        client: client.clone(),
        private_key,
    });
    let sealed_secrets = Api::<FuinSealedSecret>::all(client);

    info!("starting Fuin controller");
    Controller::new(sealed_secrets, watcher::Config::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|result| async move {
            if let Err(error) = result {
                error!(%error, "controller stream failed");
            }
            None::<()>
        })
        .for_each(|_| futures::future::ready(()))
        .await;

    Ok(())
}

async fn ensure_controller_key(client: &Client, namespace: &str) -> Result<String> {
    let private_keys: Api<FuinPrivateKey> = Api::namespaced(client.clone(), namespace);
    let (private_key, public_key) = match private_keys.get_opt(PRIVATE_KEY_NAME).await? {
        Some(key) => {
            let private_key = key.spec.private_key;
            let public_key = encryption::public_key(&private_key)?;
            (private_key, public_key)
        }
        None => {
            let keypair = encryption::generate_keypair();
            let mut key = FuinPrivateKey::new(
                PRIVATE_KEY_NAME,
                FuinPrivateKeySpec {
                    private_key: keypair.private_key.clone(),
                },
            );
            key.metadata.namespace = Some(namespace.to_owned());
            match private_keys.create(&PostParams::default(), &key).await {
                Ok(_) => (keypair.private_key, keypair.public_key),
                Err(kube::Error::Api(response)) if response.code == 409 => {
                    let existing = private_keys.get(PRIVATE_KEY_NAME).await?;
                    let public_key = encryption::public_key(&existing.spec.private_key)?;
                    (existing.spec.private_key, public_key)
                }
                Err(error) => return Err(error.into()),
            }
        }
    };

    let public_keys: Api<FuinPublicKey> = Api::all(client.clone());
    let public_key = FuinPublicKey::new(PUBLIC_KEY_NAME, FuinPublicKeySpec { public_key });
    public_keys
        .patch(
            PUBLIC_KEY_NAME,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(public_key),
        )
        .await?;

    info!(namespace, "controller key is ready");
    Ok(private_key)
}

async fn reconcile(sealed_secret: Arc<FuinSealedSecret>, context: Arc<Context>) -> Result<Action> {
    match reconcile_inner(&sealed_secret, &context).await {
        Ok(action) => Ok(action),
        Err(error) => {
            if let Err(status_error) = patch_status(
                &context.client,
                &sealed_secret,
                SecretPhase::Failed,
                Some(error.to_string()),
                0,
            )
            .await
            {
                warn!(%status_error, "failed to publish failed status");
            }
            Err(error)
        }
    }
}

async fn reconcile_inner(sealed_secret: &FuinSealedSecret, context: &Context) -> Result<Action> {
    let namespace = sealed_secret.namespace().ok_or(Error::MissingNamespace)?;
    let mut data = BTreeMap::new();
    for (name, encrypted_value) in &sealed_secret.spec.encrypted_data {
        let decrypted = encryption::decrypt(&context.private_key, encrypted_value)?;
        data.insert(name.clone(), ByteString(decrypted));
    }

    let secret_name = output_secret_name(sealed_secret);
    let secret_type = sealed_secret
        .spec
        .template
        .as_ref()
        .and_then(|template| template.r#type.clone());
    let owner_reference = sealed_secret
        .controller_owner_ref(&())
        .ok_or_else(|| Error::Configuration("sealed secret has no owner reference".into()))?;
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.clone()),
            namespace: Some(namespace.clone()),
            owner_references: Some(vec![owner_reference]),
            ..ObjectMeta::default()
        },
        data: Some(data),
        immutable: None,
        string_data: None,
        type_: secret_type,
    };
    let secrets: Api<Secret> = Api::namespaced(context.client.clone(), &namespace);
    secrets
        .patch(
            &secret_name,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(secret),
        )
        .await?;

    let count = sealed_secret.spec.encrypted_data.len() as i32;
    patch_status(
        &context.client,
        sealed_secret,
        SecretPhase::Applied,
        None,
        count,
    )
    .await?;
    Ok(Action::requeue(Duration::from_secs(3600)))
}

fn output_secret_name(sealed_secret: &FuinSealedSecret) -> String {
    sealed_secret
        .spec
        .template
        .as_ref()
        .and_then(|template| template.metadata.as_ref())
        .and_then(|metadata| metadata.get("name"))
        .and_then(|name| name.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| sealed_secret.name_any())
}

async fn patch_status(
    client: &Client,
    sealed_secret: &FuinSealedSecret,
    phase: SecretPhase,
    message: Option<String>,
    data_count: i32,
) -> Result<()> {
    let namespace = sealed_secret.namespace().ok_or(Error::MissingNamespace)?;
    let sealed_secrets: Api<FuinSealedSecret> = Api::namespaced(client.clone(), &namespace);
    let status = FuinSealedSecretStatus {
        phase: Some(phase),
        message,
        data_count: Some(data_count),
        observed_generation: sealed_secret.metadata.generation,
        conditions: Vec::new(),
    };
    sealed_secrets
        .patch_status(
            &sealed_secret.name_any(),
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(json!({
                "apiVersion": "fuin.abr.sh/v1alpha1",
                "kind": "FuinSealedSecret",
                "status": status,
            })),
        )
        .await?;
    Ok(())
}

fn error_policy(
    sealed_secret: Arc<FuinSealedSecret>,
    error: &Error,
    _context: Arc<Context>,
) -> Action {
    warn!(name = %sealed_secret.name_any(), %error, "reconciliation failed");
    Action::requeue(Duration::from_secs(30))
}
