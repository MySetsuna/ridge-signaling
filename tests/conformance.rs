//! 跨语言 golden-fixture conformance（Rust 侧）。
//!
//! `fixtures/signaling/*.json` 是**权威线形语料**：锁死现网字节形状（含 `peerPresent`
//! camelCase、cid 的"省略 vs 携带"两态、ice 的显式 `candidate:null`）。TS 侧（FIX-3，
//! wind 仓）加载**同一份** fixtures 做对称断言，保证四端线形逐字一致、不再漂移。

use ridge_signaling::{error_code, tags, Role, SignalMsg};
use serde_json::Value;

/// 编译期内联一个 fixture 文件内容。
macro_rules! fixture {
    ($f:literal) => {
        include_str!(concat!("../fixtures/signaling/", $f))
    };
}

/// 解析→序列化→再解析，断言与原 JSON **语义等价**（按 `serde_json::Value` 比较，
/// 规避对象键序/空白差异；只校验结构与值）。
fn assert_roundtrip(name: &str, json: &str) {
    let msg: SignalMsg =
        serde_json::from_str(json).unwrap_or_else(|e| panic!("[{name}] parse failed: {e}\n{json}"));
    let back = serde_json::to_string(&msg).expect("serialize");
    let a: Value = serde_json::from_str(json).unwrap();
    let b: Value = serde_json::from_str(&back).unwrap();
    assert_eq!(
        a, b,
        "[{name}] roundtrip mismatch\n in: {json}\nout: {back}"
    );
}

#[test]
fn all_fixtures_roundtrip() {
    let cases: &[(&str, &str)] = &[
        ("welcome_host", fixture!("welcome_host.json")),
        ("welcome_controller", fixture!("welcome_controller.json")),
        (
            "peer_join_controller",
            fixture!("peer_join_controller.json"),
        ),
        ("peer_join_host", fixture!("peer_join_host.json")),
        (
            "peer_leave_controller",
            fixture!("peer_leave_controller.json"),
        ),
        ("peer_leave_host", fixture!("peer_leave_host.json")),
        ("error", fixture!("error.json")),
        ("offer_no_cid", fixture!("offer_no_cid.json")),
        ("offer_cid", fixture!("offer_cid.json")),
        ("answer_cid", fixture!("answer_cid.json")),
        ("ice_null", fixture!("ice_null.json")),
        ("ice_candidate_cid", fixture!("ice_candidate_cid.json")),
        ("kick", fixture!("kick.json")),
        ("e2ee_pubkey_no_cid", fixture!("e2ee_pubkey_no_cid.json")),
        ("e2ee_pubkey_cid", fixture!("e2ee_pubkey_cid.json")),
    ];
    for (name, json) in cases {
        assert_roundtrip(name, json.trim());
    }
}

#[test]
fn cid_is_omitted_when_none_and_carried_when_some() {
    // host welcome：无 cid 字段（skip_serializing_if）；peerPresent 保持 camelCase。
    let host: SignalMsg = serde_json::from_str(fixture!("welcome_host.json")).unwrap();
    let s = serde_json::to_string(&host).unwrap();
    assert!(!s.contains("\"cid\""), "host welcome 必须省略 cid: {s}");
    assert!(
        s.contains("\"peerPresent\""),
        "必须保留 camelCase peerPresent: {s}"
    );

    // controller welcome：携带 cid。
    let ctrl: SignalMsg = serde_json::from_str(fixture!("welcome_controller.json")).unwrap();
    let s2 = serde_json::to_string(&ctrl).unwrap();
    assert!(
        s2.contains("\"cid\":\"cK7MQ2X9\""),
        "controller welcome 必须携带 cid: {s2}"
    );
}

#[test]
fn controller_offer_omits_cid() {
    // controller→host 的 offer 发出时不带 cid（由 relay 加盖）。
    let m: SignalMsg = serde_json::from_str(fixture!("offer_no_cid.json")).unwrap();
    let s = serde_json::to_string(&m).unwrap();
    assert!(!s.contains("\"cid\""), "controller offer 不应带 cid: {s}");
}

#[test]
fn ice_end_of_candidates_keeps_explicit_null() {
    // ice 候选收集结束发 candidate:null（**显式 null，非省略**）——接收端据此判定结束。
    let m: SignalMsg = serde_json::from_str(fixture!("ice_null.json")).unwrap();
    let s = serde_json::to_string(&m).unwrap();
    assert!(
        s.contains("\"candidate\":null"),
        "ice 结束帧必须序列化为 candidate:null: {s}"
    );
}

#[test]
fn unknown_tag_is_graceful_err() {
    // 前向兼容：未知 `t` → 反序列化 Err（调用方捕获并忽略，与四端现状一致），绝不 panic。
    let r: Result<SignalMsg, _> = serde_json::from_str(fixture!("unknown_forward_compat.json"));
    assert!(r.is_err(), "未知 tag 应为优雅 Err，由调用方忽略");
}

#[test]
fn variant_tags_match_wire() {
    // 锁死各变体的 `t` 串（kebab-case + 显式 rename）与现网一致。
    let kick = SignalMsg::Kick { cid: "c1".into() };
    assert!(serde_json::to_string(&kick)
        .unwrap()
        .contains("\"t\":\"kick\""));

    let pj = SignalMsg::PeerJoin {
        role: Role::Controller,
        cid: Some("c1".into()),
    };
    assert!(serde_json::to_string(&pj)
        .unwrap()
        .contains("\"t\":\"peer-join\""));

    let pl = SignalMsg::PeerLeave {
        role: Role::Host,
        cid: None,
    };
    assert!(serde_json::to_string(&pl)
        .unwrap()
        .contains("\"t\":\"peer-leave\""));

    let e = SignalMsg::E2eePubkey {
        pubkey: "x".into(),
        cid: None,
    };
    assert!(serde_json::to_string(&e)
        .unwrap()
        .contains("\"t\":\"e2ee-pubkey\""));

    // Role 线上小写。
    assert_eq!(serde_json::to_string(&Role::Host).unwrap(), "\"host\"");
    assert_eq!(
        serde_json::to_string(&Role::Controller).unwrap(),
        "\"controller\""
    );
}

#[test]
fn role_helpers() {
    assert_eq!(Role::parse("host"), Some(Role::Host));
    assert_eq!(Role::parse("controller"), Some(Role::Controller));
    assert_eq!(Role::parse("nope"), None);
    assert_eq!(Role::Host.peer(), Role::Controller);
    assert_eq!(Role::Host.as_str(), "host");
}

#[test]
fn tag_registry_has_no_collisions() {
    // 单一 tag 注册表的价值点：握手 + mux tag 数值不得撞车。
    let all = [
        tags::handshake::LEGACY_PUBKEY,
        tags::handshake::DEVICE_BOUND,
        tags::mux::PANE_RAW,
        tags::mux::JSON,
        tags::mux::CONTROL,
        tags::mux::TERMINAL_SEMANTIC,
    ];
    let mut seen = std::collections::HashSet::new();
    for t in all {
        assert!(seen.insert(t), "tag 撞车: {t:#x}");
    }
    // 钉死数值，防未来误改。
    assert_eq!(tags::handshake::LEGACY_PUBKEY, 0x01);
    assert_eq!(tags::handshake::DEVICE_BOUND, 0x02);
    assert_eq!(tags::mux::PANE_RAW, 0x10);
    assert_eq!(tags::mux::JSON, 0x11);
    assert_eq!(tags::mux::CONTROL, 0x12);
    assert_eq!(tags::mux::TERMINAL_SEMANTIC, 0x13);
}

#[test]
fn error_code_constants_match_wire() {
    assert_eq!(error_code::KICKED, "KICKED");
    assert_eq!(
        error_code::CONTROLLER_LIMIT_REACHED,
        "CONTROLLER_LIMIT_REACHED"
    );
    assert_eq!(error_code::SIGNATURE_INVALID, "SIGNATURE_INVALID");
}
