use clap::{App, Arg};
use flatten_json::flatten;
use genet_kernel::{
    profile::Profile,
    session::{Callback, Event, Session},
};
use genet_sdk::package::Package;
use serde_json::{self, json, Value};
use std::{fs::File, io::Read};
use term_grid::{Direction, Filling, Grid, GridOptions};

#[derive(Clone)]
struct SessionCallback {}

impl Callback for SessionCallback {
    fn on_event(&self, event: Event) {
        if let Event::Frames(_len) = event {}
    }
}

fn main() -> std::io::Result<()> {
    let grid = Grid::new(GridOptions {
        filling: Filling::Spaces(1),
        direction: Direction::LeftToRight,
    });
    println!("{}", grid.fit_into_width(64).unwrap());

    let packages: Vec<Package> = vec![include!(concat!(env!("OUT_DIR"), "/builtin_packages.rs"))];

    let mut profile = Profile::default();
    for pkg in packages.into_iter() {
        profile.register_package(pkg);
    }

    let matches = App::new("genet CLI")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .get_matches();

    if let Some(file) = matches.value_of("config") {
        let mut file = File::open(file)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let v: Value = serde_json::from_str(&contents).unwrap();
        let mut f = json!({});

        flatten(&v, &mut f, None, false);
        if let Some(obj) = f.as_object() {
            for (key, value) in obj {
                profile.set_config(key, &format!("{}", value));
            }
        }
    }

    let _session = Session::new(profile, SessionCallback {});

    Ok(())
}
