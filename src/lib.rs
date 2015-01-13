#![crate_type="dylib"]
#![feature(plugin_registrar)]
#![deny(warnings)]
#![allow(unstable)]

extern crate syntax;
extern crate serialize;
extern crate sodiumoxide;
#[macro_use] extern crate rustc;

use std::borrow::ToOwned;
use std::io::File;
use syntax::ast;
use syntax::visit;
use syntax::attr::AttrMetaMethods;
use syntax::codemap::Span;
use rustc::lint::{Context, LintPass, LintPassObject, LintArray};
use rustc::plugin::Registry;
use rustc::session::Session;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::{PublicKey, SecretKey};

use validator::Validator;

mod validator;

fn read_key(sess: &Session, buf: &mut [u8], filename: &str) {
    let mut file = match File::open(&Path::new(filename)) {
        Err(e) => {
            sess.err(format!("could not open key file {}: {:?}", filename, e).as_slice());
            return;
        }
        Ok(f) => f,
    };
    match file.read(buf) {
        Ok(n) if n == buf.len() => (),
        r => sess.err(format!("could not read full key from key file {}: got {:?}",
                filename, r).as_slice()),
    }
}

fn write_key(buf: &[u8], path: &Path) {
    let mut file = File::create(path).unwrap();
    file.write(buf).unwrap();
}

/// Generate a key pair and write it out as two files.
pub fn gen_keypair(pubkey: &Path, seckey: &Path) {
    let (pk, sk) = sign::gen_keypair();
    write_key(pk.0.as_slice(), pubkey);
    write_key(sk.0.as_slice(), seckey);
}

#[plugin_registrar]
pub fn plugin_registrar(reg: &mut Registry) {
    sodiumoxide::init();

    let mut pubkey = None;
    let mut seckey = None;
    {
        let args = match reg.args().meta_item_list() {
            Some(args) => args,
            None => {
                reg.sess.span_err(reg.args().span,
                    r#"usage: #[plugin(public_key="filename", ...)]"#);
                return;
            }
        };

        macro_rules! read_key {
            ($attr:expr, $size:expr) => ({
                let mut k = [0u8; $size];
                if let Some(filename) = $attr.value_str() {
                    read_key(reg.sess, k.as_mut_slice(), filename.get());
                    Some(k)
                } else {
                    None
                }
            });
        }

        for attr in args.iter() {
            if attr.check_name("public_key") {
                pubkey = read_key!(attr, sign::PUBLICKEYBYTES);
            } else if attr.check_name("secret_key") {
                seckey = read_key!(attr, sign::SECRETKEYBYTES);
            } else {
                reg.sess.span_err(attr.span, "unknown argument");
            }
        }
    }

    let pubkey = match pubkey {
        None => {
            reg.sess.span_err(reg.args().span, "public key must be specified");
            return;
        }
        Some(k) => k,
    };

    let pass = Pass {
        authenticated_parent: None,
        pubkey: PublicKey(pubkey),
        seckey: seckey.map(|k| SecretKey(k)),
    };

    reg.register_lint_pass(Box::new(pass) as LintPassObject);
}

// Is `child` a child of `parent` in the AST?
fn child_of(cx: &Context, child: ast::NodeId, parent: ast::NodeId) -> bool {
    let mut id = child;
    loop {
        if id == parent { return true; }
        match cx.tcx.map.get_parent(id) {
            i if i == id => return false, // no parent
            i => id = i,
        }
    }
}

// Grab a span of bytes from the original source file.
fn snip(cx: &Context, span: Span) -> Vec<u8> {
    match cx.sess().codemap().span_to_snippet(span) {
        None => {
            cx.sess().span_err(span, "can't get snippet");
            vec![]
        }
        Some(s) => s.into_bytes(),
    }
}

declare_lint!(UNAUTHORIZED_UNSAFE, Warn, "unauthorized unsafe blocks");
declare_lint!(WRONG_LAUNCH_CODE, Warn, "incorrect #[launch_code] attributes");

struct Pass {
    authenticated_parent: Option<ast::NodeId>,
    pubkey: PublicKey,
    seckey: Option<SecretKey>,
}

impl Pass {
    // Warn if this AST node does not have an authenticated ancestor.
    fn authorize(&self, cx: &Context, span: Span, id: ast::NodeId) {
        if match self.authenticated_parent {
            None => true,
            Some(p) => !child_of(cx, id, p),
        } {
            cx.span_lint(UNAUTHORIZED_UNSAFE, span, "unauthorized unsafe block");
        }
    }

    // Check a function's #[launch_code] attribute, if any.
    fn authenticate(&mut self,
                    cx: &Context,
                    attrs: &[ast::Attribute],
                    span: Span,
                    id: ast::NodeId) {
        let mut launch_code = None;
        let mut val = Validator::new();

        for attr in attrs.iter() {
            if attr.check_name("launch_code") {
                let value = attr.value_str()
                    .map(|s| s.get().to_owned())
                    .unwrap_or_else(|| "".to_owned());
                launch_code = Some((attr.span, value));
            } else {
                // Authenticate all attributes other than #[launch_code] itself.
                // This includes doc comments and attribute order.
                val.write(snip(cx, attr.span).as_slice());
            }
        }

        let launch_code = match launch_code {
            Some(c) => c,
            None => return,
        };

        // Authenticate the function arguments and body.
        val.write(snip(cx, span).as_slice());

        if val.verify(launch_code.1.as_slice(), &self.pubkey) {
            self.authenticated_parent = Some(id);
        } else {
            let msg = match self.seckey.as_ref() {
                None => "incorrect launch code".to_owned(),
                Some(sk) => format!("correct launch code is {}", val.compute(sk)),
            };
            cx.span_lint(WRONG_LAUNCH_CODE, launch_code.0, msg.as_slice());
        }
    }
}

impl LintPass for Pass {
    fn get_lints(&self) -> LintArray {
        lint_array!(UNAUTHORIZED_UNSAFE, WRONG_LAUNCH_CODE)
    }

    fn check_block(&mut self,
                   cx: &Context,
                   block: &ast::Block) {
        match block.rules {
            ast::DefaultBlock => (),
            ast::UnsafeBlock(..) => self.authorize(cx, block.span, block.id),
        }
    }

    fn check_fn(&mut self,
                cx: &Context,
                fk: visit::FnKind,
                _: &ast::FnDecl,
                _: &ast::Block,
                span: Span,
                id: ast::NodeId) {
        if match fk {
            visit::FkItemFn(_, _, ast::Unsafety::Unsafe, _) => true,
            visit::FkItemFn(..) => false,
            visit::FkMethod(_, _, m) => match m.node {
                ast::MethDecl(_, _, _, _, ast::Unsafety::Unsafe, _, _, _) => true,
                ast::MethDecl(..) => false,
                ast::MethMac(..) => cx.sess().bug("method macro remains during lint pass"),
            },

            // closures inherit unsafety from the context
            visit::FkFnBlock => false,
        } {
            self.authorize(cx, span, id);
        }
    }

    fn check_ty_method(&mut self, cx: &Context, m: &ast::TypeMethod) {
        self.authenticate(cx, &m.attrs[], m.span, m.id);
    }

    fn check_trait_method(&mut self, cx: &Context, it: &ast::TraitItem) {
        match *it {
            ast::RequiredMethod(ref m) => self.authenticate(cx, &m.attrs[], m.span, m.id),
            ast::ProvidedMethod(ref m) => self.authenticate(cx, &m.attrs[], m.span, m.id),
            ast::TypeTraitItem(..) => (),
        }
    }

    fn check_item(&mut self, cx: &Context, it: &ast::Item) {
        self.authenticate(cx, &it.attrs[], it.span, it.id);
    }
}
