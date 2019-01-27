use serde_derive::Deserialize;
use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::Path,
};
use toml;

#[derive(Deserialize)]
struct Cargo {
    package: Package,
}

#[derive(Deserialize)]
struct Package {
    metadata: Metadata,
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<String>,
}

fn main() -> std::io::Result<()> {
    let src = env::var("CARGO_MANIFEST_DIR").unwrap();
    let file = Path::new(&src).join("Cargo.toml");
    let mut file = File::open(file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let data: Cargo = toml::from_str(&contents).unwrap();

    let dst = env::var("OUT_DIR").unwrap();
    let file = Path::new(&dst).join("builtin_packages.rs");
    let mut file = File::create(&file)?;

    for pkg in data.package.metadata.packages {
        file.write_all(&pkg.as_bytes())?;
        file.write_all(b"::DefaultPackage::default().into(),\n")?;
    }

    Ok(())
}
