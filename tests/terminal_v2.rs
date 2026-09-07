use ridge_signaling::tags;
use ridge_signaling::terminal_v2::{
    decode_frame, encode_frame, CursorShape, DecodeError, PaneRef, ScreenKind, ScreenSnapshot,
    TerminalBody, TerminalEnvelope, TerminalSnapshot, WireCell, WireCursor, WireLine,
    PROTOCOL_VERSION,
};

fn sample_snapshot() -> TerminalSnapshot {
    let screen = ScreenSnapshot {
        lines: vec![WireLine {
            cells: vec![WireCell::blank()],
            wrapped: false,
        }],
        cursor: WireCursor {
            row: 0,
            col: 0,
            visible: true,
            blink: false,
            shape: CursorShape::Block,
        },
        saved_cursor: None,
        scroll_top: 0,
        scroll_bottom: 0,
    };
    TerminalSnapshot {
        revision: 7,
        rows: 1,
        cols: 1,
        active_screen: ScreenKind::Primary,
        primary: screen.clone(),
        alternate: screen,
        scrollback: Vec::new(),
        scrollback_start: 0,
        modes: Vec::new(),
        title: "ridge".into(),
        cwd: "/repo".into(),
        hyperlinks: Vec::new(),
    }
}

#[test]
fn snapshot_roundtrip_keeps_full_pane_identity() {
    let original =
        TerminalEnvelope::snapshot(PaneRef::new("workspace-a", "pane-a"), 41, sample_snapshot());
    let bytes = encode_frame(&original).expect("encode");
    assert_eq!(bytes[0], tags::mux::TERMINAL_SEMANTIC);
    assert_eq!(decode_frame(&bytes).expect("decode"), original);
}

#[test]
fn rejects_legacy_raw_and_protocol_skew() {
    assert_eq!(
        decode_frame(&[tags::mux::PANE_RAW]),
        Err(DecodeError::WrongTag(tags::mux::PANE_RAW))
    );

    let mut envelope =
        TerminalEnvelope::snapshot(PaneRef::new("workspace-a", "pane-a"), 1, sample_snapshot());
    envelope.version = PROTOCOL_VERSION + 1;
    let bytes = encode_frame(&envelope).expect("encode");
    assert_eq!(
        decode_frame(&bytes),
        Err(DecodeError::UnsupportedVersion(PROTOCOL_VERSION + 1))
    );
}

#[test]
fn rejects_identity_without_workspace_or_pane() {
    for pane in [PaneRef::new("", "pane-a"), PaneRef::new("workspace-a", "")] {
        let bytes =
            encode_frame(&TerminalEnvelope::snapshot(pane, 1, sample_snapshot())).expect("encode");
        assert_eq!(decode_frame(&bytes), Err(DecodeError::InvalidPaneRef));
    }
}

#[test]
fn snapshot_wire_shape_matches_golden_hex() {
    let envelope =
        TerminalEnvelope::snapshot(PaneRef::new("workspace-a", "pane-a"), 41, sample_snapshot());
    let actual = encode_frame(&envelope)
        .expect("encode")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        actual,
        include_str!("../fixtures/terminal-v2/snapshot.hex").trim()
    );
}

#[test]
fn snapshot_body_is_not_an_implicit_delta() {
    let envelope =
        TerminalEnvelope::snapshot(PaneRef::new("workspace-a", "pane-a"), 41, sample_snapshot());
    assert!(matches!(envelope.body, TerminalBody::Snapshot(_)));
}
