use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use hns_p2p_experimental::RegistryDocument;

const REGISTRY_TOML: &str = "registry/denuo-experimental-v1.toml";
const REGISTRY_BINARY: &str = "registry/denuo-experimental-v1.bin";
const REGISTRY_DIGEST: &str = "registry/denuo-experimental-v1.sha256";

fn main() -> Result<(), Box<dyn Error>> {
    let check = match env::args().nth(1).as_deref() {
        None => false,
        Some("--check") => true,
        Some(argument) => {
            return Err(format!("unknown argument {argument:?}; expected --check").into());
        }
    };
    let root = workspace_root()?;
    let input_path = root.join(REGISTRY_TOML);
    let binary_path = root.join(REGISTRY_BINARY);
    let digest_path = root.join(REGISTRY_DIGEST);

    let input = fs::read_to_string(&input_path)?;
    let registry = RegistryDocument::from_toml(&input)?;
    let binary = registry.canonical_bytes()?;
    let digest = format!("{}  denuo-experimental-v1.bin\n", registry.id()?);

    if check {
        compare(&binary_path, &binary)?;
        compare(&digest_path, digest.as_bytes())?;
        RegistryDocument::from_canonical_bytes(&fs::read(&binary_path)?)?;
        println!("registry artifacts verified: {}", registry.id()?);
    } else {
        fs::write(&binary_path, &binary)?;
        fs::write(&digest_path, digest)?;
        println!("registry artifacts generated: {}", registry.id()?);
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
