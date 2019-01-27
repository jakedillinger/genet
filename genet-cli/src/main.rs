use eth;
use genet_kernel::profile::Profile;
use genet_sdk::package::Package;

fn main() {
    let packages: Vec<Package> = vec![include!(concat!(env!("OUT_DIR"), "/builtin_packages.rs"))];
    let mut prof = Profile::default();
    for pkg in packages.into_iter() {
        prof.register_package(pkg);
    }
    println!("Hello, world!");
}
