// Copyright 2022-2024, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro/blob/master/LICENSE

use eyre::Result;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};
use structopt::StructOpt;
use stylus::{
    brotli::{self, Dictionary},
    native,
};

#[derive(StructOpt)]
#[structopt(name = "reactivate")]
struct Opts {
    data: PathBuf,
}

fn main() -> Result<()> {
    let opts = Opts::from_args();
    let file = BufReader::new(File::open(opts.data)?);
    let mut count = 0;
    let mut brotli = 0;
    let mut error = 0;

    for line in file.lines() {
        let line = line?;
        count += 1;
        if count % 500 == 0 {
            println!("activated {count} programs");
        }

        let wasm = hex::decode(line)?;
        let Ok(wasm) = brotli::decompress(&wasm, Dictionary::Empty) else {
            brotli += 1;
            println!("skipping invalid brotli {:.2}", 100. * brotli as f64 / count as f64);
            continue;
        };

        let mut gas = u64::MAX;
        if let Err(err) = native::activate(&wasm, 1, 128, false, &mut gas) {
            println!("caught: {err:?}");
            error += 1;
        }
    }
    println!("finished activating {count} programs");
    println!("    {error} were invalid brotli");
    println!("    {brotli} were invalid wasms");
    Ok(())
}
