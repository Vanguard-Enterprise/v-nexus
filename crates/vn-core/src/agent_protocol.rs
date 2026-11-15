//! The agent WebSocket protocol: subprotocol names, close codes, the message envelope,
//! and the control messages that start and run a connection.
//!
//! Messages are JSON text frames. Each one is an [`Envelope`] whose `type` names the
//! message and whose `seq` counts messages per connection and direction, from 1. Bodies
//! are typed by implementing [`Message`]. Receivers ignore unknown fields, so no body
//! type denies them. Inventory and job messages add their own [`Message`] types and
//! variants of [`AgentMessage`] and [`ServerMessage`].

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Prefix of the WebSocket subprotocol naming a major protocol version.
pub const SUBPROTOCOL_PREFIX: &str = "vn-agent.v";

/// Message size limit the server announces by default (1 MiB).
pub const DEFAULT_MAX_MESSAGE_BYTES: u32 = 1024 * 1024;

/// The subprotocol for a major version, for example `vn-agent.v1`.
pub fn subprotocol(version: u32) -> String {
    format!("{SUBPROTOCOL_PREFIX}{version}")
}

/// The major version a subprotocol names, or `None` when it is not a `vn-agent.v<N>`
/// name in canonical form (decimal, no leading zero).
pub fn parse_subprotocol(value: &str) -> Option<u32> {
    let digits = value.strip_prefix(SUBPROTOCOL_PREFIX)?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if !canonical {
        return None;
    }
    digits.parse().ok()
}

/// WebSocket close codes with a protocol meaning. The agent action for each is in the
/// close code table of `docs/agent-protocol.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseCode {
    /// The peer broke the protocol. The agent reconnects with backoff.
    ProtocolError,
    /// The session is invalid or expired. The agent requests a new session.
    SessionInvalid,
    /// The agent is revoked. The agent stops and reports that it needs re-enrollment.
    Revoked,
    /// A newer connection for the same agent replaced this one. The agent backs off.
    Superseded,
    /// The agent reported an identity, such as a cluster fingerprint, that differs from
    /// its registration. The agent stops and reports the mismatch.
    IdentityMismatch,
}

impl CloseCode {
    pub const ALL: [CloseCode; 5] = [
        CloseCode::ProtocolError,
        CloseCode::SessionInvalid,
        CloseCode::Revoked,
        CloseCode::Superseded,
        CloseCode::IdentityMismatch,
    ];

    pub const fn code(self) -> u16 {
        match self {
            CloseCode::ProtocolError => 4000,
            CloseCode::SessionInvalid => 4001,
            CloseCode::Revoked => 4003,
            CloseCode::Superseded => 4009,
            CloseCode::IdentityMismatch => 4010,
        }
    }

    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.code() == code)
    }
}

/// One message on the wire: `{"type": "...", "seq": 1, "body": {...}}`.
///
/// `Envelope` (with a JSON body) is what a receiver parses first, to check `seq` before it
/// interprets the body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope<B = Value> {
    #[serde(rename = "type")]
    pub kind: String,
    pub seq: u64,
    pub body: B,
}

impl Envelope {
    /// Parses a text frame. Fails when the frame is not an envelope, not when its type
    /// is unknown.
    pub fn parse(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
}

/// A message body with its wire `type`.
pub trait Message: Serialize + DeserializeOwned {
    const TYPE: &'static str;
}

/// Encodes `body` as the text frame of message `seq`.
pub fn encode<M: Message>(seq: u64, body: &M) -> String {
    let envelope = Envelope {
        kind: M::TYPE.to_owned(),
        seq,
        body,
    };
    serde_json::to_string(&envelope).expect("message bodies serialize to JSON")
}

fn body<M: Message>(body: Value) -> Result<M, serde_json::Error> {
    serde_json::from_value(body)
}

/// Capability strings exchanged in [`Welcome`] and [`Hello`]. Version 1 defines none
/// yet; they gate optional behavior added within the major version.
pub type Capabilities = Vec<String>;

/// Server to agent, first message of every connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    pub connection_id: Uuid,
    /// Orders this connection's observations after those of every earlier connection
    /// for the same source.
    pub sync_epoch: u64,
    /// How often the server pings. The server closes a connection that carries no
    /// traffic for three intervals.
    pub heartbeat_interval_seconds: u32,
    /// Most unacknowledged messages the agent may have in flight.
    pub ack_window: u32,
    /// Largest message the server accepts, in bytes.
    pub max_message_bytes: u32,
    pub capabilities: Capabilities,
}

impl Message for Welcome {
    const TYPE: &'static str = "welcome";
}

/// Agent to server, first message of every connection, sent after [`Welcome`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub agent_version: String,
    pub capabilities: Capabilities,
    /// Must equal the fingerprint registered at enrollment (the `kube-system` namespace
    /// UID), or the server closes the connection with [`CloseCode::IdentityMismatch`].
    pub cluster_fingerprint: String,
    /// The Kubernetes API server's `gitVersion`, for example `v1.35.0`, when the agent
    /// could read it.
    pub kubernetes_version: Option<String>,
}

impl Message for Hello {
    const TYPE: &'static str = "hello";
}

/// Either direction: a problem with one message. The connection continues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorMessage {
    /// Machine-readable code, such as [`ErrorMessage::UNSUPPORTED_TYPE`].
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// `seq` of the message the error is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_seq: Option<u64>,
}

impl ErrorMessage {
    /// The receiver does not know the message type. It ignored the message.
    pub const UNSUPPORTED_TYPE: &'static str = "unsupported_type";

    /// Answer to a message of a type the receiver does not know.
    pub fn unsupported_type(kind: &str, ref_seq: u64) -> Self {
        Self {
            code: Self::UNSUPPORTED_TYPE.to_owned(),
            message: Some(format!("unsupported message type `{kind}`")),
            ref_seq: Some(ref_seq),
        }
    }
}

impl Message for ErrorMessage {
    const TYPE: &'static str = "error";
}

/// Server to agent: every agent message up to and including `seq` is durable.
/// Acknowledgements are cumulative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub seq: u64,
}

impl Message for Ack {
    const TYPE: &'static str = "ack";
}

/// A message from an agent, typed by its envelope `type`.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentMessage {
    Hello(Hello),
    Error(ErrorMessage),
    /// A type this build does not know. The receiver answers
    /// [`ErrorMessage::unsupported_type`] and continues.
    Unknown {
        kind: String,
    },
}

impl AgentMessage {
    /// Interprets an envelope's body by its type. Fails when the body does not match a
    /// known type, which is a protocol error.
    pub fn from_envelope(envelope: Envelope) -> Result<Self, serde_json::Error> {
        Ok(match envelope.kind.as_str() {
            Hello::TYPE => AgentMessage::Hello(body(envelope.body)?),
            ErrorMessage::TYPE => AgentMessage::Error(body(envelope.body)?),
            _ => AgentMessage::Unknown {
                kind: envelope.kind,
            },
        })
    }
}

/// A message from the server, typed by its envelope `type`.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerMessage {
    Welcome(Welcome),
    Ack(Ack),
    Error(ErrorMessage),
    /// A type this build does not know. The agent answers
    /// [`ErrorMessage::unsupported_type`] and continues.
    Unknown {
        kind: String,
    },
}

impl ServerMessage {
    /// Interprets an envelope's body by its type. Fails when the body does not match a
    /// known type, which is a protocol error.
    pub fn from_envelope(envelope: Envelope) -> Result<Self, serde_json::Error> {
        Ok(match envelope.kind.as_str() {
            Welcome::TYPE => ServerMessage::Welcome(body(envelope.body)?),
            Ack::TYPE => ServerMessage::Ack(body(envelope.body)?),
            ErrorMessage::TYPE => ServerMessage::Error(body(envelope.body)?),
            _ => ServerMessage::Unknown {
                kind: envelope.kind,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn subprotocol_names_round_trip() {
        assert_eq!(subprotocol(1), "vn-agent.v1");
        assert_eq!(parse_subprotocol("vn-agent.v1"), Some(1));
        assert_eq!(parse_subprotocol("vn-agent.v12"), Some(12));
        for bad in [
            "vn-agent.v",
            "vn-agent.v01",
            "vn-agent.v1 ",
            "vn-agent.v+1",
            "vn-agent.1",
            "VN-AGENT.V1",
            "vn-agent.v99999999999",
        ] {
            assert_eq!(parse_subprotocol(bad), None, "{bad}");
        }
    }

    #[test]
    fn close_codes_round_trip() {
        for code in CloseCode::ALL {
            assert_eq!(CloseCode::from_code(code.code()), Some(code));
        }
        assert_eq!(CloseCode::from_code(1000), None);
        assert_eq!(CloseCode::Superseded.code(), 4009);
    }

    #[test]
    fn envelope_wire_format() {
        let text = encode(7, &Ack { seq: 3 });
        assert_eq!(text, r#"{"type":"ack","seq":7,"body":{"seq":3}}"#);
        let envelope = Envelope::parse(&text).unwrap();
        assert_eq!(envelope.seq, 7);
        assert_eq!(
            ServerMessage::from_envelope(envelope).unwrap(),
            ServerMessage::Ack(Ack { seq: 3 })
        );
    }

    #[test]
    fn unknown_types_and_fields_are_tolerated() {
        let envelope = Envelope::parse(r#"{"type":"later","seq":2,"body":{"x":1}}"#).unwrap();
        assert_eq!(
            AgentMessage::from_envelope(envelope).unwrap(),
            AgentMessage::Unknown {
                kind: "later".into()
            }
        );
        let hello = json!({
            "type": "hello",
            "seq": 1,
            "extra": true,
            "body": {
                "agent_version": "0.1.0",
                "capabilities": [],
                "cluster_fingerprint": "uid",
                "kubernetes_version": null,
                "future_field": 1,
            },
        });
        let envelope: Envelope = serde_json::from_value(hello).unwrap();
        assert!(matches!(
            AgentMessage::from_envelope(envelope).unwrap(),
            AgentMessage::Hello(Hello {
                kubernetes_version: None,
                ..
            })
        ));
    }

    #[test]
    fn malformed_bodies_and_envelopes_fail() {
        let envelope = Envelope::parse(r#"{"type":"hello","seq":1,"body":{}}"#).unwrap();
        assert!(AgentMessage::from_envelope(envelope).is_err());
        assert!(Envelope::parse(r#"{"type":"hello","body":{}}"#).is_err());
        assert!(Envelope::parse(r#"{"type":"hello","seq":-1,"body":{}}"#).is_err());
        assert!(Envelope::parse("not json").is_err());
    }

    #[test]
    fn error_messages_omit_absent_fields() {
        assert_eq!(
            encode(
                1,
                &ErrorMessage {
                    code: "x".into(),
                    message: None,
                    ref_seq: None
                }
            ),
            r#"{"type":"error","seq":1,"body":{"code":"x"}}"#
        );
        let unsupported = ErrorMessage::unsupported_type("later", 4);
        assert_eq!(unsupported.code, "unsupported_type");
        assert_eq!(unsupported.ref_seq, Some(4));
    }
}
