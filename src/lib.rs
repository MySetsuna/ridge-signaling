//! `ridge-signaling` —— Ridge 远控**信令 WebSocket** 消息的单一事实来源（SSOT）。
//!
//! ## 为什么存在
//! 审核（`wind/.agent-team/findings-align.md`）发现同一信令契约被 **4 处各自手写**并已
//! 漂移：relay `ridge-cloud/src/ws/messages.rs`、桌面 host `ridgeCloudProvider.ts`、桌面
//! controller `controllerCloudProvider.ts`、无头 `ridge-cli/src/signaling.rs`。其中
//! ridge-cli **全程缺 `cid`** 导致浏览器 controller 连不上（P0）。本 crate 把信令消息
//! schema 收敛为唯一定义，四端共用，并由 golden-fixture 跨语言 conformance 钉死线形。
//!
//! ## 三层协议边界
//! - **A 层 信令 JSON**（relay WebSocket 文本帧，relay 只读 `t`/`cid` 路由）→ **本 crate**。
//! - **B 层 E2EE 握手二进制首帧**（DataChannel，加密前，relay 不经手）→ `e2ee.ts`/`e2ee.rs`。
//! - **C 层 E2EE 内明文 mux**（DataChannel，加密后）→ `cloudMux.ts`/`mux.rs` + SessionControl。
//! - **终端语义与字节输入** → [`terminal`]：桌面、LAN、Cloud 共用，传输不重建历史。
//!
//! 跨层的**二进制 tag** 与 **CONTROL 子类型**、**信令错误码**集中登记在 [`tags`] /
//! [`control`] / [`error_code`]，作为防 tag 撞车的单一注册表（实际编解码器仍在各层 SSOT）。
//!
//! ## 零信任不变量
//! relay 对信令仅读 `t`/`cid` 路由，**零解析其余字段**。加密绑定材料（设备身份 Ed25519
//! 签名、TOTP 信道绑定 MAC）**全部承载在 DataChannel 内**（B/C 层），永不进本 crate 的
//! 信令 JSON —— relay 碰不到任何密码学材料（详见 crypto 设计 §7）。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

pub mod terminal;

/// 房间内 controller 寻址 id（relay 注入/读取）。
///
/// **安全约束**：cid 仅用于房间内寻址，由 relay 控制；客户端**不得**据 cid 做任何信任
/// 决策（信任来自 B 层设备身份签名 / C 层 TOTP 绑定，不来自 cid）。
pub type Cid = String;

/// 房间内角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum Role {
    Host,
    Controller,
}

impl Role {
    /// 线上字符串（`"host"` / `"controller"`）。
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Host => "host",
            Role::Controller => "controller",
        }
    }

    /// 从线上字符串解析。
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "host" => Some(Role::Host),
            "controller" => Some(Role::Controller),
            _ => None,
        }
    }

    /// 房间内的对端角色。
    pub fn peer(self) -> Role {
        match self {
            Role::Host => Role::Controller,
            Role::Controller => Role::Host,
        }
    }
}

/// 信令消息（tag 字段为 `t`，kebab-case）。
///
/// **四端唯一定义**：relay 发出连接事件（welcome/peer-join/peer-leave/error）；两端互发
/// 并由 relay 按 `cid` 路由转发（offer/answer/ice/e2ee-pubkey）；host 发 kick。
///
/// `cid` 寻址规则（§5.3，relay 权威）：
/// - controller→host（offer/ice/e2ee-pubkey）：客户端发**不带** cid；relay **加盖**该
///   controller 的 cid 后转发给 host。
/// - host→controller（answer/ice/e2ee-pubkey/kick）：host **必带** cid；relay 按 cid 定向
///   投递；**缺失/未知 cid → relay 丢弃该帧**（这正是旧 ridge-cli 连不上的根因）。
/// - 服务端事件：welcome.cid = controller 自身 cid（host 收到为 None）；peer-join/leave 的
///   cid = 该 controller 的 cid（role=host 时为 None）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "t", rename_all = "kebab-case")]
#[ts(export)]
pub enum SignalMsg {
    /// 服务端→客户端：连接成功。`peer_present` = 对端是否已在房。
    Welcome {
        room: String,
        role: Role,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[ts(optional)]
        cid: Option<Cid>,
        #[serde(rename = "peerPresent")]
        peer_present: bool,
    },
    /// 服务端→客户端：对端入房。
    PeerJoin {
        role: Role,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[ts(optional)]
        cid: Option<Cid>,
    },
    /// 服务端→客户端：对端离房。
    PeerLeave {
        role: Role,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[ts(optional)]
        cid: Option<Cid>,
    },
    /// 服务端→客户端：错误（`code` 见 [`error_code`]）。
    Error {
        code: String,
        #[serde(default)]
        message: String,
    },
    /// controller→host：SDP offer（relay 加盖 cid 转发）。
    Offer {
        sdp: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[ts(optional)]
        cid: Option<Cid>,
    },
    /// host→controller：SDP answer（host 必带 cid，relay 按 cid 投递）。
    Answer {
        sdp: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[ts(optional)]
        cid: Option<Cid>,
    },
    /// 两端互发：ICE candidate（`null` = 候选收集结束）。
    Ice {
        candidate: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[ts(optional)]
        cid: Option<Cid>,
    },
    /// host→relay：主动断开某 controller（必带 cid）。
    Kick { cid: Cid },
    /// 临时 X25519 公钥的带外旁路（§7.3 B3 防 relay-MITM）。
    ///
    /// **现状**：在设备身份强绑定（B 层 DataChannel 0x02 握手帧，见 crypto §7）落地后，
    /// 本帧降级为**兼容旧端的 relay-trust 交叉校验**通道。relay 仅读 `t`/`cid` 路由、
    /// **零解析 `pubkey`**；设备身份签名**不在此帧**（走 0x02），故本变体保持最小。
    #[serde(rename = "e2ee-pubkey")]
    E2eePubkey {
        pubkey: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[ts(optional)]
        cid: Option<Cid>,
    },
}

impl SignalMsg {
    /// 序列化为 JSON 文本帧（序列化失败降级为最小错误帧，与 relay 既有行为一致）。
    pub fn to_text(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"t":"error","code":"INTERNAL","message":"serialize failed"}"#.to_string()
        })
    }
}

/// 协议二进制 tag 注册表（**防跨层撞车的单一登记处**）。
///
/// 仅常量登记：实际编解码器在各自 SSOT —— 握手帧在 `e2ee.ts`/`e2ee.rs`，mux 在
/// `cloudMux.ts`/`packages/ridge-cli/src/mux.rs`。本模块让四端引用同一组数值，杜绝
/// 未来新增 tag 时与既有 tag 冲突。握手 tag（加密前）与 mux tag（加密后明文）处于
/// **不同相位**，不共享线上字节空间，但统一登记以防混淆。
pub mod tags {
    /// DataChannel **加密前**握手首帧（B 层）。
    pub mod handshake {
        /// 旧·裸临时公钥：`0x01 || eph_pub(32)` = 33B。
        pub const LEGACY_PUBKEY: u8 = 0x01;
        /// 新·带设备身份签名：`0x02 || eph_pub(32) || id_pub(32) || sig(64)` = 129B
        /// （字节布局 + Ed25519 验签由 crypto 在 `e2ee.*` 定义）。
        pub const DEVICE_BOUND: u8 = 0x02;
    }
    /// DataChannel **加密后**明文 mux（C 层）。
    pub mod mux {
        /// 某 pane 的裸 PTY 字节：`0x10 || paneIdLen(1) || paneId || raw`。
        pub const PANE_RAW: u8 = 0x10;
        /// UTF-8 JSON：JSON-RPC 2.0 业务信封。
        pub const JSON: u8 = 0x11;
        /// UTF-8 JSON：会话控制（[`crate::control`] 子类型）。
        pub const CONTROL: u8 = 0x12;
        /// Canonical terminal semantic frame (same codec on desktop/LAN/Cloud).
        pub const TERMINAL: u8 = crate::terminal::MUX_TAG;
    }
}

/// 0x12 CONTROL 通道子类型（JSON 的 `t` tag）。
pub mod control {
    /// 旧·明文 6 位 TOTP（回退路径）：`{ "t":"totp-verify", "code":"123456" }`。
    pub const TOTP_VERIFY: &str = "totp-verify";
    /// 新·TOTP 信道绑定 MAC（crypto §7）：`{ "t":"totp-bind", "tag":"<base64 HMAC>" }`。
    pub const TOTP_BIND: &str = "totp-bind";
    /// host→controller 验证结果：`{ "t":"totp-result", "ok":true }`。
    pub const TOTP_RESULT: &str = "totp-result";
}

/// 信令错误码（relay 在 [`SignalMsg::Error`] 中发出）。前后端共用字符串常量。
pub mod error_code {
    /// host 主动 kick 某 controller。
    pub const KICKED: &str = "KICKED";
    /// controller 数量达上限。
    pub const CONTROLLER_LIMIT_REACHED: &str = "CONTROLLER_LIMIT_REACHED";
    /// 旧·单控制方顶替（§5.3 多控制方后已不用，保留常量供历史兼容）。
    pub const REPLACED: &str = "REPLACED";
    /// 设备身份签名/绑定校验失败（语义见契约 §2；实际失败信号落 host 端 `$/bye`，
    /// **不经 relay**——此常量仅作语义登记，relay 不主动发它）。
    pub const SIGNATURE_INVALID: &str = "SIGNATURE_INVALID";
}
