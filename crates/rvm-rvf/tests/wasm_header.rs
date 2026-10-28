//! rvm#84 item 2: WASM segments written by `rvf-runtime`'s `RvfStore::embed_wasm`
//! carry a 64-byte `WasmHeader` (magic `RVWM`) in front of the bytecode. RVM
//! verifies and strips it; the header bytes never reach the WASM parser, and a
//! header that lies about the bytes after it is refused.
//!
//! `fixtures/runtime-embed-wasm.rvf` was written by a real `embed_wasm` call
//! (rvf-runtime 0.4.0 from crates.io, `fixtures/generator/embed_wasm.rs`, see
//! `fixtures/README.md`); `runtime-embed-wasm.module.wasm` is the module that
//! was embedded.

use rvm_rvf::format::SEG_TYPE_WASM;
use rvm_rvf::testkit::{minimal_container, unsigned_segment};
use rvm_rvf::{
    split_wasm_payload, verify, walk, CheckKind, DetailCode, Outcome, VerificationReport,
    VerifyOptions, WasmPayloadError, WASM_HEADER_LEN, WASM_HEADER_MAGIC,
};

const EMBED: &[u8] = include_bytes!("fixtures/runtime-embed-wasm.rvf");
const MODULE: &[u8] = include_bytes!("fixtures/runtime-embed-wasm.module.wasm");

fn dev() -> VerifyOptions {
    // embed_wasm writes an unsigned segment: only a development posture admits it.
    VerifyOptions {
        allow_unsigned_executable: true,
        ..VerifyOptions::default()
    }
}

fn payload_of_fixture() -> Vec<u8> {
    let segs = walk(EMBED).expect("rvf-runtime 0.4.0 output walks");
    let wasm = segs.iter().find(|s| s.is_executable()).unwrap();
    wasm.payload(EMBED).to_vec()
}

/// A container whose WASM segment carries `payload` verbatim, with a valid
/// content hash, so only the WasmHeader rules can refuse it.
fn container_with(payload: &[u8]) -> Vec<u8> {
    let mut d = minimal_container("memory");
    d.extend(unsigned_segment(SEG_TYPE_WASM, payload, 3));
    d
}

fn header_of(bytecode_len: u32) -> Vec<u8> {
    let mut h = vec![0u8; WASM_HEADER_LEN];
    h[..4].copy_from_slice(&WASM_HEADER_MAGIC.to_le_bytes());
    h[4] = 1;
    h[0x0C..0x10].copy_from_slice(&bytecode_len.to_le_bytes());
    h
}

fn check(report: &VerificationReport, kind: CheckKind) -> Vec<(Outcome, DetailCode)> {
    report
        .records
        .iter()
        .filter(|r| r.check == kind)
        .map(|r| (r.outcome, r.detail))
        .collect()
}

#[test]
fn the_fixture_really_has_an_rvwm_header_in_front_of_the_module() {
    let p = payload_of_fixture();
    assert_eq!(&p[..4], b"MWVR", "0x5256574D little endian");
    assert_eq!(p.len(), WASM_HEADER_LEN + MODULE.len());
    assert_eq!(&p[WASM_HEADER_LEN..], MODULE);
    // This is the bug: the whole payload is not a module.
    assert_ne!(&p[..4], b"\0asm");
}

#[test]
fn an_embed_wasm_package_is_admitted_and_binds_the_module_not_the_header() {
    let r = verify(EMBED, &dev()).unwrap();
    assert!(r.ok, "{:?}", r.failures());
    assert!(r.admissible());
    assert_eq!(
        check(&r, CheckKind::WasmHeader),
        [(Outcome::Pass, DetailCode::WasmHeaderAccepted)]
    );
    let exe = r
        .executables
        .iter()
        .find(|e| e.segment_type == SEG_TYPE_WASM)
        .unwrap();
    assert_eq!(exe.module_offset, WASM_HEADER_LEN as u64);
    assert_eq!(exe.module_length, MODULE.len() as u64);
    assert_eq!(exe.byte_length, (WASM_HEADER_LEN + MODULE.len()) as u64);
    // The identity the host checks bytes against is the code, not the header.
    assert!(exe.matches(MODULE));
    assert!(!exe.matches(&payload_of_fixture()));
    assert!(exe.matches_payload(&payload_of_fixture()));
}

#[test]
fn split_wasm_payload_yields_exactly_the_embedded_module() {
    let p = payload_of_fixture();
    assert_eq!(split_wasm_payload(&p).unwrap(), MODULE);
}

#[test]
fn the_strict_default_still_refuses_the_unsigned_runtime_segment() {
    // The header is fine; the refusal is the unsigned executable, as for any
    // unsigned executable. Admitting it is a development-posture decision.
    let r = verify(EMBED, &VerifyOptions::default()).unwrap();
    assert!(!r.ok);
    assert!(r.first_failure(CheckKind::ExecutableSigned).is_some());
    assert!(r.first_failure(CheckKind::WasmHeader).is_none());
}

#[test]
fn a_raw_module_without_a_header_is_still_accepted_and_adds_no_record() {
    let d = container_with(MODULE);
    let r = verify(&d, &dev()).unwrap();
    assert!(r.ok, "{:?}", r.failures());
    assert!(check(&r, CheckKind::WasmHeader).is_empty());
    let exe = &r.executables[0];
    assert_eq!(exe.module_offset, 0);
    assert!(exe.matches(MODULE) && exe.matches_payload(MODULE));
}

fn refused(payload: &[u8], why: WasmPayloadError) {
    let r = verify(&container_with(payload), &dev()).unwrap();
    assert!(!r.ok, "{why:?} must fail the report");
    assert!(!r.admissible());
    assert_eq!(
        check(&r, CheckKind::WasmHeader),
        [(Outcome::Fail, DetailCode::WasmHeaderRejected(why))]
    );
    // Nothing runnable is recorded for a refused header.
    assert_eq!(r.executables[0].module_length, 0);
    assert!(!r.executables[0].matches(MODULE));
    assert!(!r.executables[0].matches(payload));
}

#[test]
fn a_truncated_header_is_refused() {
    let p = payload_of_fixture();
    refused(&p[..WASM_HEADER_LEN - 1], WasmPayloadError::TruncatedHeader);
    refused(&p[..4], WasmPayloadError::TruncatedHeader);
}

#[test]
fn lying_lengths_are_refused_in_both_directions() {
    let n = MODULE.len() as u32;
    for (claimed, tail) in [(n + 1, MODULE.to_vec()), (n - 1, MODULE.to_vec())] {
        let mut p = header_of(claimed);
        p.extend_from_slice(&tail);
        refused(&p, WasmPayloadError::LengthMismatch);
    }
    // Trailing bytes after the declared module (a smuggled second module).
    let mut p = header_of(n);
    p.extend_from_slice(MODULE);
    p.extend_from_slice(MODULE);
    refused(&p, WasmPayloadError::LengthMismatch);
    // Header with no module at all.
    refused(&header_of(n), WasmPayloadError::LengthMismatch);
    refused(&header_of(0), WasmPayloadError::EmptyBytecode);
}

#[test]
fn compressed_or_unknown_headers_are_refused() {
    let mut p = payload_of_fixture();
    p[0x14] = 1; // compression
    refused(&p, WasmPayloadError::Compressed);
    let mut p = payload_of_fixture();
    p[4] = 2; // header_version
    refused(&p, WasmPayloadError::UnsupportedVersion(2));
    let mut p = payload_of_fixture();
    p[0x3F] = 1; // reserved
    refused(&p, WasmPayloadError::ReservedNonZero);
}

#[test]
fn a_wrong_magic_is_not_a_header_and_is_left_to_the_wasm_parser() {
    // "RVWN" instead of "RVWM": no header, so the payload is a bare "module"
    // that rvm-wasm will refuse. rvm-rvf records nothing about a header.
    let mut p = payload_of_fixture();
    p[0] ^= 1;
    let r = verify(&container_with(&p), &dev()).unwrap();
    assert!(check(&r, CheckKind::WasmHeader).is_empty());
    assert_eq!(split_wasm_payload(&p).unwrap(), &p[..]);
}

#[test]
fn a_header_in_a_non_wasm_segment_is_not_interpreted() {
    // Only SEG_TYPE_WASM payloads are scanned.
    let mut d = minimal_container("memory");
    d.extend(unsigned_segment(0x01, &payload_of_fixture(), 3));
    let r = verify(&d, &dev()).unwrap();
    assert!(r.ok, "{:?}", r.failures());
    assert!(check(&r, CheckKind::WasmHeader).is_empty());
}
