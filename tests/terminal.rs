use ridge_signaling::terminal::*;

fn line(text: &str, wrapped: bool) -> WireLine {
    WireLine {
        cells: text
            .chars()
            .map(|ch| WireCell {
                ch,
                ..WireCell::blank()
            })
            .collect(),
        wrapped,
    }
}

fn snapshot_fixture() -> TerminalFrame {
    let cursor = WireCursor {
        row: 1,
        col: 1,
        visible: true,
        blink: false,
        shape: CursorShape::Bar,
        pending_wrap: false,
    };
    let saved = WireSavedCursor {
        row: 0,
        col: 2,
        fg: WireColor::Rgb(10, 20, 30),
        bg: WireColor::Indexed(4),
        flags: 9,
        origin: true,
        pending_wrap: true,
        app_cursor_keys: true,
    };
    let mut primary = ScreenSnapshot {
        lines: vec![line("ABC", false), line("DEF", true)],
        cursor,
        saved_cursor: Some(saved),
        scroll_top: 0,
        scroll_bottom: 1,
    };
    primary.lines[0].cells[1].hyperlink_id = Some(1);
    let alternate = ScreenSnapshot {
        lines: vec![line("   ", false), line("   ", false)],
        cursor,
        saved_cursor: None,
        scroll_top: 0,
        scroll_bottom: 1,
    };
    TerminalFrame::new(
        PaneRef::new("work", "pane"),
        "epoch-A",
        7,
        TerminalBody::Snapshot(TerminalSnapshot {
            revision: 99,
            rows: 2,
            cols: 3,
            active_screen: ScreenKind::Primary,
            primary,
            alternate,
            history: HistoryRange {
                epoch: 4,
                start: 10,
                end: 13,
            },
            scrollback_start: 12,
            scrollback: vec![line("old", true)],
            modes: vec![ModeState {
                mode: 1006,
                on: true,
            }],
            title: "fixture".into(),
            cwd: "/work".into(),
            hyperlinks: vec![Hyperlink {
                id: 1,
                uri: "https://example.com".into(),
                params: "named".into(),
            }],
        }),
    )
}

#[test]
fn snapshot_golden_roundtrip_preserves_saved_cursor_and_packet_links() {
    let frame = snapshot_fixture();
    let bytes = encode_frame(&frame).unwrap();
    assert_eq!(decode_frame(&bytes).unwrap(), frame);
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/terminal/snapshot.hex");
    if std::env::var_os("UPDATE_TERMINAL_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{hex}\n")).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap().trim(), hex);
}

#[test]
fn each_packet_owns_its_dictionary_and_history_has_no_live_revision_gate() {
    let mut cell = WireCell::blank();
    cell.ch = '中';
    cell.width = 2;
    cell.hyperlink_id = Some(1);
    let mut continuation = WireCell::blank();
    continuation.ch = '\0';
    continuation.width = 0;
    continuation.hyperlink_id = Some(1);
    let page = HistoryPage {
        history: HistoryRange {
            epoch: 4,
            start: 10,
            end: 13,
        },
        start: 10,
        lines: vec![WireLine {
            cells: vec![cell, continuation],
            wrapped: true,
        }],
        hyperlinks: vec![Hyperlink {
            id: 1,
            uri: "https://history.example".into(),
            params: "history".into(),
        }],
    };
    let frame = TerminalFrame::new(
        PaneRef::new("work", "pane"),
        "epoch-A",
        7,
        TerminalBody::HistoryPage(page),
    );
    assert_eq!(decode_frame(&encode_frame(&frame).unwrap()).unwrap(), frame);
    let mut missing = frame.clone();
    let TerminalBody::HistoryPage(page) = &mut missing.body else {
        unreachable!()
    };
    page.hyperlinks.clear();
    assert_eq!(
        encode_frame(&missing),
        Err(ProtocolError::Invalid("missing link definition"))
    );
}

#[test]
fn rejects_invalid_identity_revision_ranges_and_trailing_or_foreign_frames() {
    let frame = snapshot_fixture();
    let mut bytes = encode_frame(&frame).unwrap();
    bytes.push(0);
    assert_eq!(
        decode_frame(&bytes),
        Err(ProtocolError::Invalid("trailing bytes"))
    );
    assert_eq!(
        decode_frame(&[MUX_TAG, 2]),
        Err(ProtocolError::UnsupportedVersion(2))
    );
    let mut invalid = frame.clone();
    invalid.terminal_epoch.clear();
    assert_eq!(
        encode_frame(&invalid),
        Err(ProtocolError::Invalid("terminal identity"))
    );
    let mut invalid = frame;
    let TerminalBody::Snapshot(snapshot) = &mut invalid.body else {
        unreachable!()
    };
    snapshot.scrollback_start = 11;
    assert_eq!(
        encode_frame(&invalid),
        Err(ProtocolError::Invalid("snapshot history range"))
    );
    let delta = TerminalFrame::new(
        PaneRef::new("work", "pane"),
        "epoch-A",
        7,
        TerminalBody::Delta(TerminalDeltaFrame {
            base_revision: 8,
            revision: 8,
            history: HistoryRange {
                epoch: 0,
                start: 0,
                end: 0,
            },
            deltas: vec![],
            hyperlinks: vec![],
        }),
    );
    assert_eq!(
        encode_frame(&delta),
        Err(ProtocolError::Invalid("live revision"))
    );
}

#[test]
fn binary_mouse_input_and_lifetime_fences_survive_json_rpc() {
    let input = TerminalInput {
        pane: PaneRef::new("work", "pane"),
        terminal_epoch: "epoch-A".into(),
        activation_id: 7,
        source_id: "controller-A".into(),
        sequence: 1,
        bytes: vec![0x1b, b'[', b'M', 0x20, 0xff, 0x80],
    };
    validate_input(&input).unwrap();
    let json = serde_json::to_string(&input).unwrap();
    assert_eq!(serde_json::from_str::<TerminalInput>(&json).unwrap(), input);
    for (source, epoch, activation) in [("bad/source".to_owned(), "epoch".to_owned(), 7), ("s".repeat(65), "epoch".to_owned(), 7), ("source".to_owned(), "e".repeat(257), 7), ("source".to_owned(), "epoch".to_owned(), 0)] {
        let mut invalid = input.clone();
        invalid.source_id = source; invalid.terminal_epoch = epoch; invalid.activation_id = activation;
        assert!(validate_input(&invalid).is_err());
    }
    let mut invalid = input;
    invalid.bytes = vec![0; MAX_INPUT_BYTES + 1];
    assert_eq!(
        validate_input(&invalid),
        Err(ProtocolError::Invalid("terminal input"))
    );
    let request = HistoryRequest {
        pane: PaneRef::new("work", "pane"),
        terminal_epoch: "epoch-A".into(),
        activation_id: 7,
        history_epoch: 4,
        before: 12,
        max_rows: MAX_HISTORY_PAGE_ROWS,
    };
    validate_history_request(&request).unwrap();
    let mut invalid = request;
    invalid.max_rows += 1;
    assert_eq!(
        validate_history_request(&invalid),
        Err(ProtocolError::Invalid("history request"))
    );
}

#[test]
fn hello_fixture_is_generated_from_the_same_contract_constants() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/terminal/hello.json");
    let hello = TerminalHello::default();
    if std::env::var_os("UPDATE_TERMINAL_FIXTURES").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&hello).unwrap() + "\n").unwrap();
    }
    let fixture: TerminalHello =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(fixture, hello);
}
