use rvf_runtime::{RvfOptions, RvfStore};
use std::path::Path;

/// (module (func (export "run")))
const MODULE: [u8; 33] = [
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
    0x03, 0x02, 0x01, 0x00, // func
    0x07, 0x07, 0x01, 0x03, b'r', b'u', b'n', 0x00, 0x00, // export "run"
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code
];

fn main() {
    let out = std::env::args().nth(1).expect("output dir");
    let module = &MODULE[..];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("embed.rvf");
    let opts = RvfOptions { dimension: 4, ..Default::default() };
    let mut s = RvfStore::create(&p, opts).unwrap();
    // role 0 = Microkernel, target 0 = Wasm32, no features, 1 export,
    // priority 0, interpreter_type 0.
    s.embed_wasm(0, 0, 0, module, 1, 0, 0).unwrap();
    s.close().unwrap();
    let bytes = std::fs::read(&p).unwrap();
    std::fs::write(Path::new(&out).join("runtime-embed-wasm.rvf"), &bytes).unwrap();
    std::fs::write(Path::new(&out).join("runtime-embed-wasm.module.wasm"), module).unwrap();
    println!("{} bytes", bytes.len());
}
