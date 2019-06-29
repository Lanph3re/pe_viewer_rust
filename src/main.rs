mod pe_viewer;

use std::io;
use clap::{Arg, App, AppSettings};

fn main() -> io::Result<()> {
    let app = App::new("PEViewer-Rust")
        .setting(AppSettings::ArgRequiredElseHelp)
        .about("Command line tool to analyze PE binary")
        .version("0.1.0")
        .author("Lanph3re <dhkvmfzld@gmail.com>")
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .takes_value(true)
            .help("PE file to analyze"))
        .get_matches();

    pe_viewer::pe_viewer(app.value_of("file").unwrap())
}