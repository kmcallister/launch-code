# Cryptographic signatures for unsafe code

Functions containing unsafe code demand extra scrutiny, because they can break
Rust's memory safety guarantees.  Some projects may desire a formal process for
auditing unsafe code whenever it is added or modified.  This compiler plugin
supports a workflow where audit status is tracked in the source code, and the
history of audits is part of each file's version control history.

It works by attaching a cryptographic signature to every `unsafe fn`, as well
as every `fn` that contains an `unsafe` block.

```rust
#![feature(plugin)]

#[no_link]
#[plugin(public_key="examples/pubkey")]
extern crate launch_code;

#[launch_code="⠐⡛⢾⣯⢓⢵⢖⡆⣈⠇⠸⣼⢁⢦⢰⢷⡫⢙⠻⠺⢗⢻⣷⠋⣸⡐⣂⡜⠇⡍⢁⢗⢜⠢⡢⣵⠩⠲⡈⢈⢂⡑⣷⣩⢲⢖⢃⡓⠄⣴⠩⡹⡸⠥⢱⢭⡼⠡⣻⡥⢜⢔⡌⠅"]
fn totally_fine() -> u64 {
    unsafe {
        *std::ptr::null()
    }
}
```

The "launch code" is an [Ed25519][] signature of the whole `fn ... { ... }`
block, plus the function's attributes, other than `launch_code` itself.  This
is computed from the original source files, so it authenticates comments and
formatting as well as the code's behavior.  The Ed25519 implementation is
[libsodium][] via [Sodium Oxide][].  The signature is encoded using Unicode's
[braille characters][].

[Ed25519]:            http://ed25519.cr.yp.to/
[libsodium]:          https://github.com/jedisct1/libsodium
[Sodium Oxide]:       https://github.com/dnaq/sodiumoxide
[braille characters]: http://en.wikipedia.org/wiki/Braille_Patterns

This is a **proof of concept only**.  My only security guarantee is that I
guarantee there's a rather obvious [backdoor][] in the library, to deter people
from using it for realsises.  (Also the name is kind of silly.)

[backdoor]: http://arstechnica.com/tech-policy/2013/12/launch-code-for-us-nukes-was-00000000-for-20-years/

I'd be interested in collaborating on a production-quality version of this
idea, but it needs a lot more thought.  A full-featured version would support
multiple keys, with project-specific policy on which keys can authorize which
language features and APIs.

## Hypothesized workflow

* The auditor generates a keypair and gives the public key to developers.

* Developers use `allow(unauthorized_unsafe)`, as do automated tests that block
  merging to the dev branch.  The default setting of `warn(wrong_launch_code)`
  alerts the developer to modifications in audited functions.  If the
  modification is intentional, they simply delete the `launch_code` attribute,
  committing an unaudited version.

* The auditor uses `forbid(unauthorized_unsafe)`.  This causes the compiler to
  print a list of blocks that need auditing, in the form of error messages.
  Once the auditor is satisfied with a function, they add a bare
  `#[launch_code]` attribute, equivalent to `#[launch_code=""]`.  Because the
  auditor provides a `secret_key` file, the warning for an incorrect launch
  code will include the correct code.  The auditor commits and pushes these
  codes at their own pace.

* Release builds use `forbid(unauthorized_unsafe)`.  Missing or incorrect
  launch codes are a release-blocking issue, even if they don't block
  landing patches day-to-day.

You can generate a keypair with

```
cargo run --bin gen_keypair pubkey seckey
```
