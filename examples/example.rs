#![feature(plugin)]
#![forbid(unauthorized_unsafe)]

#[no_link]
#[plugin(public_key="examples/pubkey",
         secret_key="examples/seckey")]
extern crate launch_code;

#[launch_code="⠐⡛⢾⣯⢓⢵⢖⡆⣈⠇⠸⣼⢁⢦⢰⢷⡫⢙⠻⠺⢗⢻⣷⠋⣸⡐⣂⡜⠇⡍⢁⢗⢜⠢⡢⣵⠩⠲⡈⢈⢂⡑⣷⣩⢲⢖⢃⡓⠄⣴⠩⡹⡸⠥⢱⢭⡼⠡⣻⡥⢜⢔⡌⠅"]
fn totally_fine() -> u64 {
    unsafe {
        *std::ptr::null()
    }
}

fn main() {
    println!("{}", totally_fine());
}
