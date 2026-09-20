use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Namespace-scoped private key material used by the controller.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "fuin.abr.sh",
    version = "v1alpha1",
    kind = "FuinPrivateKey",
    namespaced,
    status = "FuinPrivateKeyStatus",
    shortname = "fpk"
)]
#[serde(rename_all = "camelCase")]
pub struct FuinPrivateKeySpec {
    pub private_key: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FuinPrivateKeyStatus {
    pub phase: Option<KeyPhase>,
    pub message: Option<String>,
    pub observed_generation: Option<i64>,
}

/// Cluster-scoped public key used by clients to encrypt values.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "fuin.abr.sh",
    version = "v1alpha1",
    kind = "FuinPublicKey",
    status = "FuinPublicKeyStatus",
    shortname = "fpubk"
)]
#[serde(rename_all = "camelCase")]
pub struct FuinPublicKeySpec {
    pub public_key: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FuinPublicKeyStatus {
    pub phase: Option<KeyPhase>,
    pub message: Option<String>,
    pub observed_generation: Option<i64>,
}

/// Namespace-scoped encrypted values that reconcile into a Kubernetes Secret.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "fuin.abr.sh",
    version = "v1alpha1",
    kind = "FuinSealedSecret",
    namespaced,
    status = "FuinSealedSecretStatus",
    shortname = "fss",
    printcolumn(json_path = ".status.phase", name = "STATUS", type_ = "string"),
    printcolumn(json_path = ".status.dataCount", name = "DATA", type_ = "integer"),
    printcolumn(
        json_path = ".metadata.creationTimestamp",
        name = "AGE",
        type_ = "date"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct FuinSealedSecretSpec {
    pub encrypted_data: BTreeMap<String, String>,
    pub template: Option<SecretTemplate>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretTemplate {
    pub metadata: Option<BTreeMap<String, Value>>,
    pub r#type: Option<String>,
    pub immutable: Option<bool>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FuinSealedSecretStatus {
    pub phase: Option<SecretPhase>,
    pub message: Option<String>,
    pub data_count: Option<i32>,
    pub observed_generation: Option<i64>,
    pub conditions: Vec<FuinCondition>,
}

/// Cluster-scoped encrypted values propagated into selected namespaces.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "fuin.abr.sh",
    version = "v1alpha1",
    kind = "FuinClusterSealedSecret",
    status = "FuinClusterSealedSecretStatus",
    shortname = "fcss",
    printcolumn(json_path = ".status.phase", name = "STATUS", type_ = "string"),
    printcolumn(
        json_path = ".status.namespaceCount",
        name = "NAMESPACES",
        type_ = "integer"
    ),
    printcolumn(
        json_path = ".metadata.creationTimestamp",
        name = "AGE",
        type_ = "date"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct FuinClusterSealedSecretSpec {
    pub encrypted_data: BTreeMap<String, String>,
    pub namespace_selector: NamespaceSelector,
    pub exclude_namespaces: Vec<String>,
    pub template: Option<SecretTemplate>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceSelector {
    pub match_labels: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FuinClusterSealedSecretStatus {
    pub phase: Option<SecretPhase>,
    pub message: Option<String>,
    pub namespace_count: Option<i32>,
    pub observed_generation: Option<i64>,
    pub conditions: Vec<FuinCondition>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum KeyPhase {
    Pending,
    Applied,
    Failed,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum SecretPhase {
    Pending,
    Applied,
    Failed,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FuinCondition {
    pub r#type: String,
    pub status: ConditionStatus,
    pub observed_generation: Option<i64>,
    pub last_transition_time: String,
    pub reason: String,
    pub message: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}
