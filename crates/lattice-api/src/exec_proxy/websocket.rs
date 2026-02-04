//! WebSocket utilities for exec/attach/portforward
//!
//! Provides helpers for working with K8s-style WebSocket messages and
//! sending close frames with proper error codes.

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures::stream::SplitSink;
use futures::SinkExt;

/// K8s WebSocket channel IDs
pub mod channel {
    /// Channel 0: stdin
    pub const STDIN: u8 = 0;
    /// Channel 1: stdout
    pub const STDOUT: u8 = 1;
    /// Channel 2: stderr
    pub const STDERR: u8 = 2;
    /// Channel 3: error
    pub const ERROR: u8 = 3;
    /// Channel 4: terminal resize
    pub const RESIZE: u8 = 4;
}

/// WebSocket close codes
pub mod close_code {
    /// Normal closure
    pub const NORMAL: u16 = 1000;
    /// Policy violation (e.g., not found)
    pub const POLICY_VIOLATION: u16 = 1008;
    /// Internal error
    pub const INTERNAL_ERROR: u16 = 1011;
}

/// Parsed K8s WebSocket message
#[derive(Debug)]
pub enum K8sMessage {
    /// Stdin data
    Stdin(Vec<u8>),
    /// Terminal resize
    Resize {
        /// Terminal width in columns
        width: u16,
        /// Terminal height in rows
        height: u16,
    },
    /// Raw data (no channel prefix)
    Raw(Vec<u8>),
}

/// Parse a K8s WebSocket binary message
///
/// K8s WebSocket protocol uses the first byte as channel ID:
/// - 0: stdin
/// - 1: stdout
/// - 2: stderr
/// - 3: error
/// - 4: terminal resize (4 bytes: width LE u16, height LE u16)
pub fn parse_k8s_message(data: &[u8]) -> Option<K8sMessage> {
    if data.is_empty() {
        return None;
    }

    let channel = data[0];
    let payload = &data[1..];

    match channel {
        channel::RESIZE if payload.len() >= 4 => {
            let width = u16::from_le_bytes([payload[0], payload[1]]);
            let height = u16::from_le_bytes([payload[2], payload[3]]);
            Some(K8sMessage::Resize { width, height })
        }
        channel::STDIN..=channel::ERROR => Some(K8sMessage::Stdin(payload.to_vec())),
        _ => Some(K8sMessage::Raw(data.to_vec())),
    }
}

/// Build a K8s WebSocket message with channel prefix
pub fn build_k8s_message(channel: u8, data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(1 + data.len());
    msg.push(channel);
    msg.extend_from_slice(data);
    msg
}

/// Send a WebSocket close frame
pub async fn send_close(
    sender: &mut SplitSink<WebSocket, Message>,
    code: u16,
    reason: impl Into<String>,
) {
    let _ = sender
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into().into(),
        })))
        .await;
}

/// Send a normal close frame
pub async fn send_close_normal(
    sender: &mut SplitSink<WebSocket, Message>,
    reason: impl Into<String>,
) {
    send_close(sender, close_code::NORMAL, reason).await;
}

/// Send an error close frame (policy violation - 1008)
pub async fn send_close_error(
    sender: &mut SplitSink<WebSocket, Message>,
    reason: impl Into<String>,
) {
    send_close(sender, close_code::POLICY_VIOLATION, reason).await;
}

/// Send an internal error close frame (1011)
pub async fn send_close_internal(
    sender: &mut SplitSink<WebSocket, Message>,
    reason: impl Into<String>,
) {
    send_close(sender, close_code::INTERNAL_ERROR, reason).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_k8s_message_stdin() {
        let data = vec![0, b'h', b'e', b'l', b'l', b'o'];
        let msg = parse_k8s_message(&data).unwrap();
        match msg {
            K8sMessage::Stdin(payload) => assert_eq!(payload, b"hello"),
            _ => panic!("Expected Stdin message"),
        }
    }

    #[test]
    fn test_parse_k8s_message_resize() {
        // Channel 4, width=80 (0x50), height=24 (0x18)
        let data = vec![4, 0x50, 0x00, 0x18, 0x00];
        let msg = parse_k8s_message(&data).unwrap();
        match msg {
            K8sMessage::Resize { width, height } => {
                assert_eq!(width, 80);
                assert_eq!(height, 24);
            }
            _ => panic!("Expected Resize message"),
        }
    }

    #[test]
    fn test_parse_k8s_message_raw() {
        let data = vec![99, 1, 2, 3]; // Unknown channel
        let msg = parse_k8s_message(&data).unwrap();
        match msg {
            K8sMessage::Raw(payload) => assert_eq!(payload, vec![99, 1, 2, 3]),
            _ => panic!("Expected Raw message"),
        }
    }

    #[test]
    fn test_parse_k8s_message_empty() {
        let data: Vec<u8> = vec![];
        assert!(parse_k8s_message(&data).is_none());
    }

    #[test]
    fn test_build_k8s_message() {
        let msg = build_k8s_message(channel::STDOUT, b"output");
        assert_eq!(msg, vec![1, b'o', b'u', b't', b'p', b'u', b't']);
    }
}
