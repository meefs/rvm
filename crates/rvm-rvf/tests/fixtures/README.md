# RVF compat fixtures

Bytes produced by the **RuVector writers**, checked in so `rvm-rvf` is tested
against the thing it restates rather than against its own test kit
(ADR-160 P0). Used by `../fixtures_compat.rs`. These are independent copies;
RuVector will later export canonical fixtures into its own repository
(ADR-354).

| File | Writer | Expected |
|---|---|---|
| `forge-signed-root-page.rvf` (4480 B) | `rvf-forge-core` `author::ContainerBuilder`, one `Wasm` segment (`\0asm\x01\0\0\0`), `sign_with(SigningKey::from_bytes(&[7u8; 32]))` | walks (2 segments + trailing 4096-byte `RVM0` page); verifies `ok` with the key below |
| `forge-signed-root-page.pubkey.hex` | the verifying key of the above | trusted key for the verify test |
| `rvstore-legacy.rvf` (841 B) | current `rvf-runtime` `RvfStore::create` + `ingest_batch` of 10 four-float vectors + `close` | **rejected**: `RvfError::BadMagic`, because the legacy dialect does not pad segments to 64 bytes (segment 1 starts at 162, the reader looks at 192). Converging the dialect is RuVector's job under ADR-354; the test pins today's behavior. |
| `runtime-embed-wasm.rvf` (640 B) | `rvf-runtime` **=0.4.0** (crates.io) `RvfStore::create` (dimension 4) + `embed_wasm(role 0, target 0, features 0, <33-byte module>, 1 export, priority 0, interpreter 0)` + `close`; generator `generator/embed_wasm.rs` | walks (manifest, WASM, manifest; no root page); the WASM payload is a 64-byte `WasmHeader` (`4D 57 56 52`, "RVWM") + the module; verifies `ok` only with `allow_unsigned_executable` (the segment is unsigned); used by `../wasm_header.rs` and `rvm-launch/tests/wasm_header_e2e.rs` |
| `runtime-embed-wasm.module.wasm` (33 B) | the module that was embedded: `(module (func (export "run")))` | what the header must be stripped down to |

sha256: `forge-signed-root-page.rvf`
`ecd4340c62c979f916665a88c03e36e7ea10e222a3c5228a12b934c1136f86a1`,
`rvstore-legacy.rvf`
`a46048da958f1cbc581f1ef77ecd3851f36bf9b4211b5556bad7fddf39e9fdb2`.

## Regenerating

`generator/` is a throwaway program (not a workspace member; it has its own
empty `[workspace]`). It adapts the Ofer interop reproducer. Its path
dependencies point at a RuVector checkout on the branch carrying ADR-353/354
(`/data/scratch/ofer-wt/ruvector` when these were made, RuVector commit
`b3fcc8520`); edit them for your machine, then:

```sh
cd crates/rvm-rvf/tests/fixtures/generator
cargo run --release -- ..
```

The Forge output is deterministic for a fixed key; the `RvfStore` file embeds
a generated file id, so regenerating it changes the bytes (and the sha256
above) while keeping the same structure and the same rejection.

`runtime-embed-wasm.rvf` embeds a generated file id and so changes if regenerated, as does
its sha256 (`006528f67aeb119d152d82069e64003944eba7aef79622c12a088d19e35e381b` as committed);
the module is fixed (`f7fb20ef0be78ab4dec443a627d3f9aa4e184bb52456b0acbb01685b97409636`). To regenerate:
create a scratch crate with `rvf-runtime = "=0.4.0"` and `tempfile`, use `generator/embed_wasm.rs` as its
`main.rs`, and run it with an output directory argument.
