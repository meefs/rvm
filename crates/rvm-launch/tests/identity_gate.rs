//! rvm#84 item 1 (ADR-160 item 8): a report whose `rvf_identity` is only the
//! signer's claim is not an admission. `ok` says the checks passed; the gate
//! that grants authority is `identity_confirmed` (`admissible()`), and every
//! path that mints a `VerifiedPackage`, hands out a module, installs
//! capabilities or starts an instance is behind it.

#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;
mod stream_common;

use rvm_cap::CapabilityTable;
use rvm_host::{HostError, VerifiedPackage, WasmAdapter};
use rvm_launch::{Instance, InstanceId, InstanceState, SessionError, SessionState};
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::StreamState;
use rvm_types::PartitionId;
use rvm_wasm::agent::AgentManager;
use rvm_witness::WitnessLog;
use stream_common::*;

fn stage_ordered(lie: Option<[u8; 32]>) -> (Streamed<'static>, Vec<u8>, Vec<u8>) {
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    let mut b = builder(12, Order::Stage);
    b.identity_override = lie;
    // Leak the key slice: the session borrows it for the whole test.
    let keys: &'static [[u8; 32]] = Box::leak(Box::new([b.public_key()]));
    let bundle = b.build(&body).unwrap();
    let mut s = stream(keys, bundle, base_policy());
    run_all(&mut s).unwrap();
    (s, body, module)
}

#[test]
fn an_unconfirmed_identity_report_is_not_admissible_and_mints_no_package() {
    let (s, body, _) = stage_ordered(None);
    assert_eq!(s.session.stream_state(), StreamState::CompleteUnverified);
    let report = s.session.report().unwrap();
    // The checks passed, so `ok` is true; that alone grants nothing.
    assert!(report.ok, "{:?}", report.failures());
    assert!(!report.identity_confirmed);
    assert!(!report.admissible());
    assert_eq!(
        VerifiedPackage::from_report(report),
        Err(HostError::IdentityUnconfirmed)
    );
    assert!(report.clone().into_result().is_err());
    // Nothing is exposed by the session either.
    assert!(s.session.package().is_none());
    let _ = body;
}

#[test]
fn nothing_activates_before_the_identity_is_confirmed_and_everything_does_after() {
    let (mut s, body, module) = stage_ordered(None);
    assert_eq!(s.session.state(), SessionState::Complete);
    // No module (the only input of start_verified), no capabilities.
    assert_eq!(
        s.session.take_module(2).err(),
        Some(SessionError::IdentityUnverified)
    );
    let mut table = CapabilityTable::<8>::new();
    assert_eq!(
        s.session
            .install_capabilities(&mut table, PartitionId::new(1), 1, 100)
            .err(),
        Some(SessionError::IdentityUnverified)
    );

    confirm(&mut s, &body);
    let report = s.session.report().unwrap();
    assert!(report.identity_confirmed && report.admissible());
    assert_eq!(s.session.stream_state(), StreamState::Complete);
    let package = s.session.package().expect("package after confirmation").clone();
    assert_eq!(package.identity(), &rvm_rvf::sha256(&body));
    assert_eq!(package, VerifiedPackage::from_report(report).unwrap());

    let vm = s.session.take_module(2).unwrap();
    let log = WitnessLog::<512>::new();
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
    assert_eq!(inst.state(), InstanceState::Running);
    assert_eq!(inst.module_bytes(), Some(module.as_slice()));
}

#[test]
fn a_lying_identity_never_yields_a_package_a_module_or_a_running_instance() {
    let (mut s, body, _) = stage_ordered(Some([0x99; 32]));
    assert_eq!(s.session.stream_state(), StreamState::CompleteUnverified);
    assert!(!s.session.report().unwrap().identity_confirmed);
    assert!(s.session.package().is_none());
    assert!(s.session.take_module(2).is_err());
    let r = s.session.finish_identity(|off, buf| {
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    });
    assert!(r.is_err());
    assert_eq!(s.session.state(), SessionState::Poisoned);
    assert!(s.session.package().is_none());
    assert!(s.session.take_module(2).is_err());
    // The poisoned stream's report does not become admissible.
    assert!(s.session.report().is_none_or(|r| !r.admissible()));
}

#[test]
fn file_order_confirms_the_identity_while_streaming() {
    let module = wasm_common::synthetic_module(3_000);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
    let mut s = stream(&keys, bundle, base_policy());
    run_all(&mut s).unwrap();
    assert_eq!(s.session.stream_state(), StreamState::Complete);
    let report = s.session.report().unwrap();
    assert!(report.identity_confirmed && report.admissible());
    assert!(s.session.package().is_some());
}
