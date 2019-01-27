use clap::App;
use genet_kernel::{
    profile::Profile,
    session::{Callback, Event, Session},
};
use genet_sdk::package::Package;
use term_grid::{Direction, Filling, Grid, GridOptions};

#[derive(Clone)]
struct SessionCallback {}

impl Callback for SessionCallback {
    fn on_event(&self, event: Event) {
        if let Event::Frames(_len) = event {}
    }
}

fn main() {
    let packages: Vec<Package> = vec![include!(concat!(env!("OUT_DIR"), "/builtin_packages.rs"))];

    let mut profile = Profile::default();
    for pkg in packages.into_iter() {
        profile.register_package(pkg);
    }
    let _session = Session::new(profile, SessionCallback {});

    let grid = Grid::new(GridOptions {
        filling: Filling::Spaces(1),
        direction: Direction::LeftToRight,
    });
    println!("{}", grid.fit_into_width(64).unwrap());

    App::new("genet CLI")
        .version(env!("CARGO_PKG_VERSION"))
        .get_matches();
}
