mod stream_common;
#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;
use rvm_host::VerifiedPackage;
use rvm_launch::{SessionError, SessionState, StreamSession};
use rvm_rvf::stream::builder::{Order, Stages, StreamBuilder, StreamBundle};
use rvm_rvf::stream::{MemoryPinStore, ReplayProtection, StreamError, StreamPolicy};
use stream_common::*;

fn pinned<'k>(keys: &'k [[u8; 32]], store: &'k MemoryPinStore) -> StreamSession<'k> {
    let mut p = StreamPolicy::new(
        keys,
        ReplayProtection::Store {
            store,
            now_ns: None,
        },
    );
    p.size = rvm_rvf::SizePolicy::permissive();
    p.size.max_segments = 4096;
    StreamSession::new(p, opts(), base_policy())
}
fn signer(epoch: u64, order: Order) -> StreamBuilder {
    let mut b = StreamBuilder::new([0x5A; 32]);
    b.chunk_log2 = 12;
    b.epoch = epoch;
    b.order = order;
    if order == Order::Stage {
        b.stages = Stages::ByType;
    }
    b
}
fn bundle_for(b: &StreamBuilder) -> (StreamBundle, Vec<u8>) {
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    (b.build(&body).unwrap(), body)
}

/// Stale-epoch (replayed) stream: session Failed(Replay), but session.report() is admissible
/// and VerifiedPackage::from_report mints a package.
#[test]
fn stale_epoch_session_report_is_still_admissible() {
    let store = MemoryPinStore::new();
    let old = signer(4, Order::File);
    let new = signer(5, Order::File);
    let keys = [old.public_key()];
    let (b_old, _) = bundle_for(&old);
    let (b_new, _) = bundle_for(&new);
    let mut s_old = pinned(&keys, &store);
    s_old.push(&b_old.frames[0]).unwrap();
    let mut s_new = pinned(&keys, &store);
    for f in &b_new.frames {
        s_new.push(f).unwrap();
    }
    let mut last = Ok(rvm_launch::SessionEvent::Descriptor);
    for f in &b_old.frames[1..] {
        last = s_old.push(f);
        if last.is_err() {
            break;
        }
    }
    assert_eq!(last, Err(SessionError::Replay(StreamError::StaleEpoch)));
    assert_eq!(s_old.state(), SessionState::Failed);
    let Some(r) = s_old.report() else { return }; // withheld: sound
    assert!(
        !r.admissible() && VerifiedPackage::from_report(r).is_err(),
        "FINDING: replayed (stale-epoch) session is Failed yet report().admissible()={} and from_report mints a package",
        r.admissible()
    );
}

/// Same through the stage-ordered path: finish_identity returns Err(Replay) after having
/// flipped report.identity_confirmed = true.
#[test]
fn stale_epoch_finish_identity_leaves_confirmed_report_behind() {
    let store = MemoryPinStore::new();
    let old = signer(4, Order::Stage);
    let new = signer(5, Order::File);
    let keys = [old.public_key()];
    let (b_old, body) = bundle_for(&old);
    let (b_new, _) = bundle_for(&new);
    let mut s_old = pinned(&keys, &store);
    s_old.push(&b_old.frames[0]).unwrap();
    let mut s_new = pinned(&keys, &store);
    for f in &b_new.frames {
        s_new.push(f).unwrap();
    }
    for f in &b_old.frames[1..] {
        s_old.push(f).unwrap();
    }
    let r = s_old.finish_identity(|off, buf| {
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    });
    assert!(
        matches!(r, Err(SessionError::Replay(StreamError::StaleEpoch))),
        "{r:?}"
    );
    assert!(s_old.package().is_none());
    assert!(s_old.take_module(2).is_err());
    let Some(rep) = s_old.report() else { return }; // withheld: sound
    assert!(
        !rep.admissible(),
        "FINDING: finish_identity failed with Replay, session Failed, report().admissible()=true"
    );
}

/// F2: `StreamComplete` is written only once the identity is confirmed (and the
/// pin passed). A stage-ordered stream whose identity then fails never carries a
/// success-looking completion record; an honest one gets exactly one, after
/// `finish_identity`.
#[test]
fn stream_complete_is_witnessed_only_after_identity_confirmation() {
    use rvm_rvf::{CheckKind, WitnessContext};
    use rvm_witness::WitnessLog;
    const CTX: WitnessContext = WitnessContext::new(1, 1);
    let completes = |log: &WitnessLog<512>| {
        (0..log.len())
            .filter_map(|i| log.get(i))
            .filter(|r| r.flags == CheckKind::StreamComplete as u8)
            .count()
    };
    for lie in [None, Some([0x99u8; 32])] {
        let mut b = signer(1, Order::Stage);
        b.identity_override = lie;
        let (bundle, body) = bundle_for(&b);
        let keys = [b.public_key()];
        let mut p = StreamPolicy::unpinned_insecure(&keys);
        p.size = rvm_rvf::SizePolicy::permissive();
        p.size.max_segments = 4096;
        let mut s = StreamSession::new(p, opts(), base_policy());
        let log = WitnessLog::<512>::new();
        for f in &bundle.frames {
            s.push_witnessed(f, &log, CTX).unwrap();
        }
        assert_eq!(completes(&log), 0, "bytes complete is not an admission");
        let r = s.finish_identity_witnessed(
            |off, buf| {
                buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
                true
            },
            &log,
            CTX,
        );
        assert_eq!(r.is_ok(), lie.is_none());
        assert_eq!(completes(&log), usize::from(lie.is_none()));
        if lie.is_some() {
            assert!(s.report().is_none());
        }
    }
}
