use eth;
use genet_kernel::profile::Profile;
use genet_sdk::package::Package;
use term_grid::{Direction, Filling, Grid, GridOptions};

fn main() {
    let packages: Vec<Package> = vec![include!(concat!(env!("OUT_DIR"), "/builtin_packages.rs"))];
    let mut prof = Profile::default();
    for pkg in packages.into_iter() {
        prof.register_package(pkg);
    }

    let grid = Grid::new(GridOptions {
        filling: Filling::Spaces(1),
        direction: Direction::LeftToRight,
    });

    println!("{}", grid.fit_into_width(64).unwrap());
}
