use fuin_controller::types::{
    FuinClusterSealedSecret, FuinPrivateKey, FuinPublicKey, FuinSealedSecret,
};
use kube::CustomResourceExt;
use serde_yaml_ng::to_string;
use std::{error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../charts/fuin/crds");
    fs::create_dir_all(&output_dir)?;

    write_crd(
        &output_dir,
        "fuinprivatekey-crd.yaml",
        FuinPrivateKey::crd(),
    )?;
    write_crd(&output_dir, "fuinpublickey-crd.yaml", FuinPublicKey::crd())?;
    write_crd(
        &output_dir,
        "fuinsealedsecret-crd.yaml",
        FuinSealedSecret::crd(),
    )?;
    write_crd(
        &output_dir,
        "fuinclustersealedsecret-crd.yaml",
        FuinClusterSealedSecret::crd(),
    )?;

    Ok(())
}

fn write_crd(
    output_dir: &std::path::Path,
    filename: &str,
    crd: impl serde::Serialize,
) -> Result<(), Box<dyn Error>> {
    let path = output_dir.join(filename);
    fs::write(path, to_string(&crd)?)?;
    Ok(())
}
