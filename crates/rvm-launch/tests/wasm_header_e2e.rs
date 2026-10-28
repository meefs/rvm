//! rvm#84 item 2, end to end: a package written by `rvf-runtime`'s
//! `embed_wasm` (a real fixture, see `rvm-rvf/tests/fixtures/README.md`) is
//! admitted by the buffered loader and by the streaming session, and the
//! WASM parser only ever sees module bytes.

mod stream_common;

use rvm_host::{VerifiedPackage, WasmAdapter};
use rvm_launch::{Instance, InstanceId, InstanceState, LaunchError, SessionError, StreamSession};
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::{StreamPolicy, StreamState};
use rvm_rvf::testkit::{unsigned_segment, unsigned_segment_with};
use rvm_rvf::{verify, VerifyOptions, WasmPayloadError, WASM_HEADER_LEN, WASM_HEADER_MAGIC};
use rvm_wasm::agent::AgentManager;
use rvm_wasm::validate_module;
use rvm_witness::WitnessLog;
use stream_common::*;

const EMBED: &[u8] = include_bytes!("../../rvm-rvf/tests/fixtures/runtime-embed-wasm.rvf");
const MODULE: &[u8] = include_bytes!("../../rvm-rvf/tests/fixtures/runtime-embed-wasm.module.wasm");

/// embed_wasm writes an unsigned executable: a development posture.
fn dev() -> VerifyOptions {
    VerifyOptions {
        allow_unsigned_executable: true,
        ..VerifyOptions::default()
    }
}

fn payload() -> Vec<u8> {
    let segs = rvm_rvf::walk(EMBED).unwrap();
    segs.iter()
        .find(|s| s.is_executable())
        .unwrap()
        .payload(EMBED)
        .to_vec()
}

#[test]
fn the_wasm_parser_refuses_the_header_and_accepts_the_module_after_it() {
    let p = payload();
    assert!(
        validate_module(&p).is_err(),
        "the whole payload is not a module"
    );
    assert!(validate_module(MODULE).is_ok());
    assert_eq!(rvm_rvf::split_wasm_payload(&p).unwrap(), MODULE);
}

#[test]
fn a_buffered_embed_wasm_package_starts_from_its_module_bytes_only() {
    let report = verify(EMBED, &dev()).unwrap();
    let package = VerifiedPackage::from_report(&report).unwrap();
    assert!(package.accepts_wasm(MODULE));
    assert!(!package.accepts_wasm(&payload()), "the header is not code");

    let log = WitnessLog::<256>::new();
    let mut agents = AgentManager::<4>::new();
    let mut inst = Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        package.clone(),
        PLACEMENT,
        &log,
        1,
    )
    .unwrap();
    // Handing the whole payload (header included) is refused, fail closed.
    assert!(inst.start(&payload(), &mut agents, &log, 2).is_err());
    assert_eq!(inst.state(), InstanceState::Created);
    inst.start(MODULE, &mut agents, &log, 3).unwrap();
    assert_eq!(inst.state(), InstanceState::Running);
    let _: Option<LaunchError> = None;
}

fn session_for<'k>(keys: &'k [[u8; 32]]) -> StreamSession<'k> {
    let mut policy = StreamPolicy::unpinned_insecure(keys);
    policy.size = rvm_rvf::SizePolicy::permissive();
    policy.size.max_segments = 4096;
    StreamSession::new(policy, dev(), base_policy())
}

/// The same real payload, re-wrapped with the SHAKE-256 checksum the stream
/// path requires for an executable (ADR-160 note 6: the runtime's default
/// checksum is refused on the stream path, whatever the payload).
fn rewrapped(payload: &[u8]) -> Vec<u8> {
    let mut d = unsigned_segment(0x07, b"rvm.capabilities=memory", 1);
    d.extend(unsigned_segment_with(0x10, payload, 2, 2));
    d.extend(unsigned_segment(0x05, b"root", 3));
    d
}

#[test]
fn a_streamed_embed_wasm_payload_is_admitted_for_every_chunk_split_and_order() {
    let body = rewrapped(&payload());
    for order in [Order::File, Order::Stage] {
        // Chunks are at least 4 KiB, so a session sees the 64-byte header whole;
        // the scanner is tested at every split in rvm-rvf (wasm_payload tests).
        for chunk_log2 in [12u8, 13, 0xFF] {
            let b = builder(chunk_log2, order);
            let keys = [b.public_key()];
            let Ok(bundle) = b.build(&body) else { continue };
            let mut s = session_for(&keys);
            for f in &bundle.frames {
                s.push(f)
                    .unwrap_or_else(|e| panic!("{order:?} {chunk_log2}: {e}"));
            }
            if s.stream_state() == StreamState::CompleteUnverified {
                s.finish_identity(|off, buf| {
                    buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
                    true
                })
                .unwrap();
            }
            let vm = s.take_module(2).unwrap();
            // The module the instance will hold is the bytecode, no header.
            assert_eq!(vm.as_bytes(), MODULE, "{order:?} {chunk_log2}");
            let package = s.package().unwrap().clone();
            let log = WitnessLog::<256>::new();
            let mut agents = AgentManager::<4>::new();
            let mut inst = Instance::create(
                InstanceId::new(1),
                WasmAdapter::new(),
                package,
                PLACEMENT,
                &log,
                1,
            )
            .unwrap();
            inst.start_verified(vm, &mut agents, &log, 2).unwrap();
            assert_eq!(inst.module_bytes(), Some(MODULE));
        }
    }
}

#[test]
fn a_streamed_header_that_lies_about_its_length_is_refused_and_yields_nothing() {
    let mut p = payload();
    // bytecode_size one larger than the bytes present.
    let n = u32::from_le_bytes(p[0x0C..0x10].try_into().unwrap());
    p[0x0C..0x10].copy_from_slice(&(n + 1).to_le_bytes());
    let body = rewrapped(&p);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let bundle = b.build(&body).unwrap();
    let mut s = session_for(&keys);
    let mut err = None;
    for f in &bundle.frames {
        if let Err(e) = s.push(f) {
            err = Some(e);
            break;
        }
    }
    assert_eq!(
        err,
        Some(SessionError::WasmHeader {
            seg_id: 2,
            error: WasmPayloadError::LengthMismatch
        })
    );
    assert!(s.take_module(2).is_err());
    assert!(s.package().is_none());
}

#[test]
fn a_streamed_header_with_extra_bytes_is_refused_and_a_truncated_one_too() {
    for (name, p, want) in [
        (
            "extra",
            {
                let mut p = payload();
                p.extend_from_slice(MODULE);
                p
            },
            WasmPayloadError::LengthMismatch,
        ),
        (
            "truncated",
            payload()[..WASM_HEADER_LEN - 5].to_vec(),
            WasmPayloadError::TruncatedHeader,
        ),
    ] {
        let body = rewrapped(&p);
        let b = builder(12, Order::File);
        let keys = [b.public_key()];
        let bundle = b.build(&body).unwrap();
        let mut s = session_for(&keys);
        let mut err = None;
        for f in &bundle.frames {
            if let Err(e) = s.push(f) {
                err = Some(e);
                break;
            }
        }
        assert_eq!(
            err,
            Some(SessionError::WasmHeader {
                seg_id: 2,
                error: want
            }),
            "{name}"
        );
        assert!(s.package().is_none(), "{name}");
    }
    let _ = WASM_HEADER_MAGIC;
}

/// What is NOT claimed: the file exactly as `embed_wasm` wrote it, streamed
/// as is. `rvf-runtime` writes the executable with its default checksum
/// (XXH3), which the stream path refuses for executables (ADR-160 note 6,
/// RF-04) whatever the payload. The buffered loader admits it (above); to
/// stream it, repackage with a SHAKE-256 checksum (`rewrapped`).
#[test]
fn the_unmodified_embed_wasm_file_is_refused_by_the_stream_path_for_its_checksum() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let bundle = b.build(EMBED).unwrap();
    let mut s = session_for(&keys);
    let mut err = None;
    for f in &bundle.frames {
        if let Err(e) = s.push(f) {
            err = Some(e);
            break;
        }
    }
    eprintln!("unmodified embed_wasm file on the stream path: {err:?}");
    assert!(err.is_some());
    assert!(s.package().is_none());
}
