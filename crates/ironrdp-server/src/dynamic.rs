//! Dynamic virtual channels opened at run time by the application.
//!
//! The server opens its own dynamic channels (input, display control, EGFX...) when the client is
//! ready. An application can open others whenever it wants by sending
//! [`ServerEvent::DynamicChannel`](crate::ServerEvent::DynamicChannel) events: the channel is
//! driven by the application's [`DvcServerProcessor`], which learns the outcome of the creation
//! through [`DvcProcessor::start`](ironrdp_dvc::DvcProcessor::start) (accepted by the client) or
//! [`DvcProcessor::creation_failed`](ironrdp_dvc::DvcProcessor::creation_failed) (declined), gets
//! the client's messages through `process`, and its end through `close`. Messages to the client
//! go through [`DynamicChannelMessage::Send`].

use core::fmt;

use ironrdp_core::{Encode, EncodeResult, WriteCursor, ensure_size};
use ironrdp_dvc::{DvcEncode, DvcServerProcessor};
use tokio::sync::oneshot;

/// An application message on a dynamic channel, sent as it is.
pub struct RawDvcMessage(pub Vec<u8>);

impl Encode for RawDvcMessage {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.0.len());
        dst.write_slice(&self.0);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawDvcMessage"
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

impl DvcEncode for RawDvcMessage {}

impl fmt::Debug for RawDvcMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RawDvcMessage").field(&self.0.len()).finish()
    }
}

/// Requests about the dynamic channels of the application.
///
/// Submit them only for an active session: the server discards channel events while idle.
pub enum DynamicChannelMessage {
    /// Sends a Create Request for the channel of `processor` (named after
    /// [`DvcProcessor::channel_name`](ironrdp_dvc::DvcProcessor::channel_name)). `reply` receives
    /// the id of the channel, or why the request couldn't be sent (no drdynvc channel, or not
    /// ready yet). The client's answer comes to the processor.
    Open {
        processor: Box<dyn DvcServerProcessor>,
        reply: oneshot::Sender<Result<u32, String>>,
    },
    /// Sends `payload` on an open channel (fragmented as needed). `completion` receives `true` once
    /// written, `false` if the channel isn't open.
    Send {
        channel_id: u32,
        payload: Vec<u8>,
        completion: oneshot::Sender<bool>,
    },
    /// Closes a channel (its processor's `close` is called if it was open).
    Close { channel_id: u32 },
}

impl fmt::Debug for DynamicChannelMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { processor, .. } => f.debug_tuple("Open").field(&processor.channel_name()).finish(),
            Self::Send {
                channel_id, payload, ..
            } => f
                .debug_struct("Send")
                .field("channel_id", channel_id)
                .field("len", &payload.len())
                .finish(),
            Self::Close { channel_id } => f.debug_struct("Close").field("channel_id", channel_id).finish(),
        }
    }
}
