use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use hns_p2p_experimental::RegistryDocument;

const REGISTRY_STEMS: [&str; 3] = [
    "denuo-experimental-v1",
    "denuo-experimental-v2",
    "hnsr-service-profiles-v1",
];

fn main() -> Result<(), Box<dyn Error>> {
    let check = match env::args().nth(1).as_deref() {
        None => false,
        Some("--check") => true,
        Some(argument) => {
            return Err(format!("unknown argument {argument:?}; expected --check").into());
        }
    };
    let root = workspace_root()?;
    for stem in REGISTRY_STEMS {
        process_registry(&root, stem, check)?;
    }
    Ok(())
}

fn process_registry(root: &Path, stem: &str, check: bool) -> Result<(), Box<dyn Error>> {
    let input_path = root.join("registry").join(format!("{stem}.toml"));
    let binary_path = root.join("registry").join(format!("{stem}.bin"));
    let digest_path = root.join("registry").join(format!("{stem}.sha256"));

    let input = fs::read_to_string(&input_path)?;
    let registry = RegistryDocument::from_toml(&input)?;
    let binary = registry.canonical_bytes()?;
    let digest = format!("{}  {stem}.bin\n", registry.id()?);

    if check {
        compare(&binary_path, &binary)?;
        compare(&digest_path, digest.as_bytes())?;
        RegistryDocument::from_canonical_bytes(&fs::read(&binary_path)?)?;
        println!("registry artifacts verified: {stem} {}", registry.id()?);
    } else {
        fs::write(&binary_path, &binary)?;
        fs::write(&digest_path, digest)?;
        println!("registry artifacts generated: {stem} {}", registry.id()?);
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .ok_or("generator is not inside the expected workspace")?
        .to_path_buf())
}

fn compare(path: &Path, expected: &[u8]) -> Result<(), Box<dyn Error>> {
    let actual = fs::read(path)?;
    if actual != expected {
        return Err(format!("{} is stale; run hns-registry-gen", path.display()).into());
    }
    Ok(())
}
