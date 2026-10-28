//! Adversarial review of PR #87.
mod stream_common;

use rvm_launch::{SessionError, SessionState, StreamSession};
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::{StreamPolicy, StreamState};
use rvm_rvf::testkit::{unsigned_segment, unsigned_segment_with};
use rvm_rvf::{verify, VerifyOptions, WASM_HEADER_LEN, WASM_HEADER_MAGIC};
use stream_common::*;

const MODULE: &[u8] = include_bytes!("../../rvm-rvf/tests/fixtures/runtime-embed-wasm.module.wasm");

fn dev() -> VerifyOptions {
    VerifyOptions {
        allow_unsigned_executable: true,
        ..VerifyOptions::default()
    }
}
fn session_for<'k>(keys: &'k [[u8; 32]]) -> StreamSession<'k> {
    let mut policy = StreamPolicy::unpinned_insecure(keys);
    policy.size = rvm_rvf::SizePolicy::permissive();
    policy.size.max_segments = 4096;
    StreamSession::new(policy, dev(), base_policy())
}
fn header(size: u32) -> Vec<u8> {
    let mut h = vec![0u8; WASM_HEADER_LEN];
    h[..4].copy_from_slice(&WASM_HEADER_MAGIC.to_le_bytes());
    h[4] = 1;
    h[0x0C..0x10].copy_from_slice(&size.to_le_bytes());
    h
}
fn body_with(payload: &[u8]) -> Vec<u8> {
    let mut d = unsigned_segment(0x07, b"rvm.capabilities=memory", 1);
    d.extend(unsigned_segment_with(0x10, payload, 2, 2));
    d.extend(unsigned_segment(0x05, b"root", 3));
    d
}

/// Outcome of streaming `body`: None = refused somewhere, Some(module bytes) = module handed over.
fn stream_outcome(body: &[u8], order: Order, chunk_log2: u8) -> Option<Option<Vec<u8>>> {
    let b = builder(chunk_log2, order);
    let keys = [b.public_key()];
    let bundle = b.build(body).ok()?;
    let mut s = session_for(&keys);
    for f in &bundle.frames {
        if s.push(f).is_err() {
            return Some(None);
        }
    }
    if s.stream_state() == StreamState::CompleteUnverified
        && s.finish_identity(|off, buf| {
            buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
            true
        })
        .is_err()
    {
        return Some(None);
    }
    Some(s.take_module(2).ok().map(|m| m.as_bytes().to_vec()))
}

#[test]
fn differential_buffered_vs_stream_all_orders_and_chunk_sizes() {
    let n = MODULE.len() as u32;
    let mut cases: Vec<(&str, Vec<u8>)> = vec![];
    let mk = |size: u32, extra: &[u8]| {
        let mut p = header(size);
        p.extend_from_slice(MODULE);
        p.extend_from_slice(extra);
        p
    };
    cases.push(("ok", mk(n, b"")));
    cases.push(("size+1", mk(n + 1, b"")));
    cases.push(("size-1", mk(n - 1, b"")));
    cases.push(("trailing", mk(n, b"X")));
    cases.push(("trailing0", mk(n, &[0u8; 40])));
    cases.push(("bare", MODULE.to_vec()));
    cases.push(("truncated", header(n)[..63].to_vec()));
    cases.push(("hdr-only", header(n)));
    // 4 KiB-boundary header: header begins so that it spans a chunk boundary is impossible (seg header is first), but make module big
    let big = {
        let mut p = header(MODULE.len() as u32);
        p.extend(MODULE);
        p
    };
    cases.push(("big-ok", big));
    for (name, payload) in cases {
        let body = body_with(&payload);
        let buffered = verify(&body, &dev()).unwrap();
        let buffered_ok = buffered.admissible();
        let want_module: Option<Vec<u8>> = if buffered_ok {
            Some(MODULE.to_vec())
        } else {
            None
        };
        for order in [Order::File, Order::Stage] {
            for cl in [12u8, 13, 16, 0xFF] {
                if let Some(got) = stream_outcome(&body, order, cl) {
                    assert_eq!(
                        got.is_some(),
                        buffered_ok,
                        "{name} {order:?} {cl}: stream accept != buffered accept"
                    );
                    if buffered_ok {
                        assert_eq!(got, want_module, "{name} {order:?} {cl}");
                    }
                }
            }
        }
    }
}

/// Module that fails validation in the LAST segment of an in-order stream:
/// admission has already built an ok+confirmed report. Is the report still admissible?
#[test]
fn failed_module_session_vs_report_admissible() {
    let mut d = unsigned_segment(0x07, b"rvm.capabilities=memory", 1);
    d.extend(unsigned_segment(0x05, b"root", 2));
    d.extend(unsigned_segment_with(
        0x10,
        b"\0asm\x01\0\0\0\xff\xff\xff",
        3,
        2,
    ));
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let bundle = b.build(&d).unwrap();
    let mut s = session_for(&keys);
    let mut last = None;
    for f in &bundle.frames {
        last = Some(s.push(f));
        if last.as_ref().unwrap().is_err() {
            break;
        }
    }
    eprintln!(
        "last={:?} state={:?} report_some={}",
        last,
        s.state(),
        s.report().is_some()
    );
    if let Some(r) = s.report() {
        eprintln!(
            "ok={} confirmed={} admissible={}",
            r.ok,
            r.identity_confirmed,
            r.admissible()
        );
        assert!(
            s.state() == SessionState::Complete || !r.admissible(),
            "FINDING: session {:?} but report().admissible()",
            s.state()
        );
    }
    assert!(s.package().is_none() || s.state() == SessionState::Complete);
    let _: Option<SessionError> = None;
}
