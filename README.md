# Fuin

Fuin encrypts Kubernetes Secrets with [age](https://age-encryption.org/) and
recreates them in the cluster through a controller.

Fuin is inspired by [Bitnami Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets),
with age encryption and a controller-managed key pair.

The encrypted field names remain readable. Only the values in
`spec.encryptedData` are encrypted.

## Install the controller

The chart installs the CRDs, service account, RBAC, and one controller pod.

Install from the Fuin Helm repository:

```sh
helm repo add fuin https://fuin.metantesan.com/
helm repo update
helm install fuin fuin/fuin \
  --namespace fuin-system \
  --create-namespace
```

For a local checkout, use the chart directory directly:

```sh
helm install fuin ./charts/fuin \
  --namespace fuin-system \
  --create-namespace \
  -f charts/fuin/values-main.yaml
```

The controller creates its private key in its own namespace. The private key
is a namespaced `FuinPrivateKey` and is never published outside the cluster.
The corresponding cluster-scoped public key is published as
`FuinPublicKey/fuin-controller`.

## Seal a Secret

Create a normal Kubernetes Secret file:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-config
  namespace: staging
type: Opaque
stringData:
  APP_ENV: staging
  API_ENDPOINT: https://api.example.com
```

Generate a `FuinSealedSecret` without changing the cluster:

```sh
fuin seal --from-file ./app-config.secret.yaml --output ./app-config.sealed.yaml
```

Apply it directly instead:

```sh
fuin seal --from-file ./app-config.secret.yaml --apply
```

The CLI also accepts an existing Secret name from the current kube context:

```sh
fuin seal app-config --namespace staging --output ./app-config.sealed.yaml
```

Both `data` and `stringData` are supported. The generated sealed resource
preserves the Secret name, namespace, type, labels, annotations, and immutable
setting through `spec.template`.

## Create a cluster-wide Secret

Use `--cluster-wide` to create a `FuinClusterSealedSecret`. An empty namespace
selector targets every namespace. Exclusions always win.

```sh
fuin seal --from-file ./app-config.secret.yaml \
  --cluster-wide \
  --exclude-namespace kube-system \
  --exclude-namespace fuin-system \
  --output ./app-config.cluster-sealed.yaml
```

Apply the cluster-wide resource:

```sh
fuin seal --from-file ./app-config.secret.yaml \
  --cluster-wide \
  --exclude-namespace kube-system \
  --exclude-namespace fuin-system \
  --apply
```

To target only namespaces with a label, repeat `--namespace-label` as needed:

```sh
fuin seal --from-file ./registry.secret.yaml \
  --cluster-wide \
  --namespace-label fuin.abr.sh/registry-access=true \
  --exclude-namespace fuin-system \
  --apply
```

The controller creates one normal Kubernetes Secret in every selected
namespace and updates the sealed resource status with the number of target
namespaces.

## Inspect resources

```sh
kubectl get fuinsealedsecrets
kubectl get fuinclustersealedsecrets
kubectl get secrets -A
kubectl describe fuinsealedsecret app-config -n staging
```

The controller records Kubernetes Events for successful and failed sealing or
reconciliation operations.

## Minikube demo

The repository includes a harmless example Secret at
`examples/minikube-secret.yaml`. Create its namespace and seal the file using
the public key from the current kube context:

```sh
# Required when Fuin was installed before the current CRDs were added.
kubectl apply -f ./charts/fuin/crds
kubectl create namespace fuin-demo --dry-run=client -o yaml | kubectl apply -f -
fuin seal --from-file ./examples/minikube-secret.yaml --apply
```

The CLI creates only the `FuinSealedSecret`; the controller decrypts it and
creates the normal Secret:

```sh
kubectl get fuinsealedsecret demo-config -n fuin-demo
kubectl get secret demo-config -n fuin-demo
kubectl describe fuinsealedsecret demo-config -n fuin-demo
```

To inspect the encrypted resource without applying it:

```sh
fuin seal --from-file ./examples/minikube-secret.yaml
```

## Development

```sh
just verify
just crds
just helm-template
```

`just crds` regenerates the CRDs from the public Rust types in
`crates/controller/src/types/mod.rs`.
