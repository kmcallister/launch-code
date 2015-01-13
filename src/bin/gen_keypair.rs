#![deny(warnings)]
#![allow(unstable)]

extern crate launch_code;

use std::{io, os};

pub fn main() {
    let args = os::args();
    match args.as_slice() {
        [_, ref pk, ref sk] => {
            launch_code::gen_keypair(&Path::new(pk), &Path::new(sk));
        }
        _ => {
            writeln!(&mut io::stderr(),
                "Usage: gen_keypair <public key filename> <secret key filename>").unwrap();
            os::set_exit_status(1);
        }
    }
}
