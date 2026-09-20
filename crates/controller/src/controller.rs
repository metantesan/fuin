use crate::types::{
    FuinClusterSealedSecret, FuinClusterSealedSecretStatus, FuinPrivateKey, FuinPrivateKeySpec,
    FuinPublicKey, FuinPublicKeySpec, FuinSealedSecret, FuinSealedSecretStatus, NamespaceSelector,
    SecretPhase, SecretTemplate,
};
use fuin_core::encryption;
use futures::StreamExt;
use k8s_openapi::{
    ByteString,
    api::core::v1::{Namespace, ObjectReference, Secret},
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{ListParams, Patch, PatchParams, PostParams},
    runtime::{
        Controller,
        controller::Action,
        events::{Event, EventType, Recorder},
        watcher,
    },
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
    recorder: Recorder,
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
        recorder: Recorder::new(client.clone(), "fuin-controller".into()),
    });
    let sealed_secrets = Api::<FuinSealedSecret>::all(client.clone());
    let cluster_sealed_secrets = Api::<FuinClusterSealedSecret>::all(client);

    info!("starting Fuin controller");
    tokio::try_join!(
        run_namespaced(sealed_secrets, context.clone()),
        run_cluster(cluster_sealed_secrets, context),
    )?;

    Ok(())
}

async fn run_namespaced(
    sealed_secrets: Api<FuinSealedSecret>,
    context: Arc<Context>,
) -> Result<()> {
    Controller::new(sealed_secrets, watcher::Config::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|result| async move {
            if let Err(error) = result {
                error!(%error, "namespaced controller stream failed");
            }
            None::<()>
        })
        .for_each(|_| futures::future::ready(()))
        .await;
    Ok(())
}

async fn run_cluster(
    cluster_sealed_secrets: Api<FuinClusterSealedSecret>,
    context: Arc<Context>,
) -> Result<()> {
    Controller::new(cluster_sealed_secrets, watcher::Config::default())
        .shutdown_on_signal()
        .run(reconcile_cluster, error_policy_cluster, context)
        .filter_map(|result| async move {
            if let Err(error) = result {
                error!(%error, "cluster controller stream failed");
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
        Ok(action) => {
            publish_event(
                &context,
                &sealed_secret.object_ref(&()),
                EventType::Normal,
                "SecretApplied",
                "Apply",
                "Decrypted values and applied the generated Kubernetes Secret".into(),
            )
            .await;
            Ok(action)
        }
        Err(error) => {
            publish_event(
                &context,
                &sealed_secret.object_ref(&()),
                EventType::Warning,
                "ReconcileFailed",
                "Reconcile",
                error.to_string(),
            )
            .await;
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

async fn publish_event(
    context: &Context,
    object_ref: &ObjectReference,
    event_type: EventType,
    reason: &str,
    action: &str,
    note: String,
) {
    let event = Event {
        type_: event_type,
        reason: reason.into(),
        note: Some(note),
        action: action.into(),
        secondary: None,
    };
    if let Err(error) = context.recorder.publish(&event, object_ref).await {
        warn!(%error, "failed to publish Kubernetes event");
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
    let template = sealed_secret.spec.template.as_ref();
    let secret_type = template.and_then(|template| template.r#type.clone());
    let immutable = template.and_then(|template| template.immutable);
    let labels = template_metadata_map(template, "labels");
    let annotations = template_metadata_map(template, "annotations");
    let owner_reference = sealed_secret
        .controller_owner_ref(&())
        .ok_or_else(|| Error::Configuration("sealed secret has no owner reference".into()))?;
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.clone()),
            namespace: Some(namespace.clone()),
            labels,
            annotations,
            owner_references: Some(vec![owner_reference]),
            ..ObjectMeta::default()
        },
        data: Some(data),
        immutable: None,
        string_data: None,
        type_: secret_type,
    };
    let secret = Secret {
        immutable,
        ..secret
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

async fn reconcile_cluster(
    sealed_secret: Arc<FuinClusterSealedSecret>,
    context: Arc<Context>,
) -> Result<Action> {
    match reconcile_cluster_inner(&sealed_secret, &context).await {
        Ok(action) => {
            publish_event(
                &context,
                &sealed_secret.object_ref(&()),
                EventType::Normal,
                "ClusterSecretApplied",
                "Apply",
                "Applied the generated Secret to selected namespaces".into(),
            )
            .await;
            Ok(action)
        }
        Err(error) => {
            publish_event(
                &context,
                &sealed_secret.object_ref(&()),
                EventType::Warning,
                "ClusterReconcileFailed",
                "Reconcile",
                error.to_string(),
            )
            .await;
            if let Err(status_error) = patch_cluster_status(
                &context.client,
                &sealed_secret,
                SecretPhase::Failed,
                Some(error.to_string()),
                0,
            )
            .await
            {
                warn!(%status_error, "failed to publish cluster secret failed status");
            }
            Err(error)
        }
    }
}

async fn reconcile_cluster_inner(
    sealed_secret: &FuinClusterSealedSecret,
    context: &Context,
) -> Result<Action> {
    let namespaces: Api<Namespace> = Api::all(context.client.clone());
    let namespaces = namespaces.list(&ListParams::default()).await?;
    let selected = namespaces
        .items
        .iter()
        .filter(|namespace| {
            namespace_selected(
                namespace,
                &sealed_secret.spec.namespace_selector,
                &sealed_secret.spec.exclude_namespaces,
            )
        })
        .collect::<Vec<_>>();

    let mut data = BTreeMap::new();
    for (name, encrypted_value) in &sealed_secret.spec.encrypted_data {
        let decrypted = encryption::decrypt(&context.private_key, encrypted_value)?;
        data.insert(name.clone(), ByteString(decrypted));
    }

    let template = sealed_secret.spec.template.as_ref();
    let secret_name = output_secret_name_from_template(template, sealed_secret.name_any());
    let owner_reference = sealed_secret.controller_owner_ref(&()).ok_or_else(|| {
        Error::Configuration("cluster sealed secret has no owner reference".into())
    })?;
    for namespace in &selected {
        let namespace_name = namespace.name_any();
        let secret = build_secret(
            &namespace_name,
            &secret_name,
            template,
            data.clone(),
            owner_reference.clone(),
        );
        let secrets: Api<Secret> = Api::namespaced(context.client.clone(), &namespace_name);
        secrets
            .patch(
                &secret_name,
                &PatchParams::apply(FIELD_MANAGER).force(),
                &Patch::Apply(secret),
            )
            .await?;
    }

    let count = selected.len() as i32;
    patch_cluster_status(
        &context.client,
        sealed_secret,
        SecretPhase::Applied,
        None,
        count,
    )
    .await?;
    Ok(Action::requeue(Duration::from_secs(3600)))
}

fn namespace_selected(
    namespace: &Namespace,
    selector: &NamespaceSelector,
    exclude_namespaces: &[String],
) -> bool {
    let name = namespace.name_any();
    if exclude_namespaces.iter().any(|excluded| excluded == &name) {
        return false;
    }
    selector.match_labels.iter().all(|(key, value)| {
        namespace
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(key))
            == Some(value)
    })
}

fn build_secret(
    namespace: &str,
    secret_name: &str,
    template: Option<&SecretTemplate>,
    data: BTreeMap<String, ByteString>,
    owner_reference: k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference,
) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_owned()),
            namespace: Some(namespace.to_owned()),
            labels: template_metadata_map(template, "labels"),
            annotations: template_metadata_map(template, "annotations"),
            owner_references: Some(vec![owner_reference]),
            ..ObjectMeta::default()
        },
        data: Some(data),
        immutable: template.and_then(|template| template.immutable),
        string_data: None,
        type_: template.and_then(|template| template.r#type.clone()),
    }
}

fn error_policy_cluster(
    sealed_secret: Arc<FuinClusterSealedSecret>,
    error: &Error,
    _context: Arc<Context>,
) -> Action {
    warn!(name = %sealed_secret.name_any(), %error, "cluster reconciliation failed");
    Action::requeue(Duration::from_secs(30))
}

async fn patch_cluster_status(
    client: &Client,
    sealed_secret: &FuinClusterSealedSecret,
    phase: SecretPhase,
    message: Option<String>,
    namespace_count: i32,
) -> Result<()> {
    let cluster_sealed_secrets: Api<FuinClusterSealedSecret> = Api::all(client.clone());
    let status = FuinClusterSealedSecretStatus {
        phase: Some(phase),
        message,
        namespace_count: Some(namespace_count),
        observed_generation: sealed_secret.metadata.generation,
        conditions: Vec::new(),
    };
    cluster_sealed_secrets
        .patch_status(
            &sealed_secret.name_any(),
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Apply(json!({
                "apiVersion": "fuin.abr.sh/v1alpha1",
                "kind": "FuinClusterSealedSecret",
                "status": status,
            })),
        )
        .await?;
    Ok(())
}

fn output_secret_name(sealed_secret: &FuinSealedSecret) -> String {
    output_secret_name_from_template(
        sealed_secret.spec.template.as_ref(),
        sealed_secret.name_any(),
    )
}

fn output_secret_name_from_template(
    template: Option<&SecretTemplate>,
    default_name: String,
) -> String {
    template
        .and_then(|template| template.metadata.as_ref())
        .and_then(|metadata| metadata.get("name"))
        .and_then(|name| name.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or(default_name)
}

fn template_metadata_map(
    template: Option<&crate::types::SecretTemplate>,
    field: &str,
) -> Option<BTreeMap<String, String>> {
    let values = template?.metadata.as_ref()?.get(field)?.as_object()?;
    let result = values
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
        .collect::<BTreeMap<_, _>>();
    (!result.is_empty()).then_some(result)
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
