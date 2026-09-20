default: check

# Format every Rust crate.
fmt:
    cargo fmt --all

# Verify Rust formatting without changing files.
fmt-check:
    cargo fmt --all -- --check

# Check all workspace crates.
check:
    cargo check --workspace

# Run all Rust tests.
test:
    cargo test --workspace

# Generate Helm CRDs from the public Rust types.
crds:
    cargo run -p crdgen

# Lint the Helm chart.
helm-lint:
    helm lint charts/fuin

# Render the chart, including CRDs, for inspection.
helm-template:
    helm template fuin charts/fuin --include-crds

# Package the chart into dist/.
package: crds helm-lint
    mkdir -p dist
    helm package charts/fuin --destination dist

# Run the controller binary.
controller:
    cargo run -p fuin_controller

# Run the checks used before committing changes.
verify: fmt-check check helm-lint
