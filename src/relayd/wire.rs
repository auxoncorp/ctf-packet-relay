//! lttng-relayd wire protocol types
//!
//! All fields are big-endian

use std::{fmt, io};
use std::{marker::Unpin, num::NonZeroU64};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

// Compatible with lttng version 2.10+
pub const VERSION_MAJOR: u32 = 2;
pub const VERSION_MINOR: u32 = 10;

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ErrorCode(pub u32);

impl ErrorCode {
    /// LTTNG_OK variant of `enum lttng_error_code`
    pub const OK: Self = ErrorCode(10);

    pub fn is_ok(&self) -> bool {
        *self == Self::OK
    }

    pub fn check(&self) -> Result<(), LttngRelaydError> {
        if self.is_ok() {
            Ok(())
        } else {
            Err(LttngRelaydError(*self))
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Error)]
#[error("Received an lttng-relayd error code ({})", _0.0)]
pub struct LttngRelaydError(pub ErrorCode);

/// Session handle created by the relayd
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct SessionId(u64);

/// Stream ID known by the relayd
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct StreamId(u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Network sequence number, per stream
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct NetworkSequenceNumber(pub u64);

impl NetworkSequenceNumber {
    pub const NONE: Self = Self(u64::MAX);

    pub fn increment(&mut self) {
        self.0 = self.0.saturating_add(1);
    }

    pub fn previous(&self) -> Self {
        Self(self.0.saturating_sub(1))
    }
}

/// Index data
///
/// lttng-relayd writes packet index files that track indices
/// of CTF packets in the stream files
///
/// This is the public portion of that index, the CTF packet fields.
/// The other fields are managed internally by the client.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Index {
    /// Note that a zero-sized packet is a "live beacon"
    /// which isn't a thing we're supporting currently
    pub packet_size_bits: NonZeroU64,
    pub content_size_bits: u64,
    pub timestamp_begin: u64,
    pub timestamp_end: u64,
    pub events_discarded: OptionalIndexField,
    /// stream_id here is the CTF metadata stream class ID
    pub stream_id: u64,
    pub stream_instance_id: OptionalIndexField,
    pub packet_seq_num: OptionalIndexField,
}

impl fmt::Display for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{stream_id={}, packet_size={}, content_size={}, clock_begin={}, clock_end={}, discarded={}, seq_num={}}}",
            self.stream_id,
            self.packet_size_bits,
            self.content_size_bits,
            self.timestamp_begin,
            self.timestamp_end,
            self.events_discarded,
            self.packet_seq_num,
        )
    }
}

/// The type of an optional field in `Index`
/// When fields are not avilable (None), the wire value is u64::MAX
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct OptionalIndexField(u64);

impl OptionalIndexField {
    pub const fn none() -> Self {
        Self(u64::MAX)
    }

    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl From<Option<u64>> for OptionalIndexField {
    fn from(value: Option<u64>) -> Self {
        match value {
            Some(v) => Self::new(v),
            None => Self::none(),
        }
    }
}

impl fmt::Display for OptionalIndexField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            u64::MAX => f.write_str("NA"),
            _ => self.0.fmt(f),
        }
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Command {
    AddStream = 1,
    CreateSession = 2,
    StartData = 3,
    Version = 5,
    SendMetadata = 6,
    CloseStream = 7,
    SendIndex = 13,
    StreamsSent = 16,
}

impl Command {
    fn into_wire(self) -> u32 {
        self as u32
    }
}

/// `struct lttcomm_relayd_hdr`
pub struct ControlHeader;

impl ControlHeader {
    pub async fn write<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        cmd: Command,
        data_size: u64,
    ) -> io::Result<()> {
        debug!(
            "Writing ControlHeader cmd={:?}, data_size={}",
            cmd, data_size
        );
        w.write_u64(0).await?; // circuit_id unused
        w.write_u64(data_size).await?;
        w.write_u32(cmd.into_wire()).await?;
        w.write_u32(0).await?; // cmd_version unused
        Ok(())
    }
}

/// `struct lttcomm_relayd_data_hdr`
pub struct DataHeader;

impl DataHeader {
    pub async fn write<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        stream_id: StreamId,
        net_seq_num: NetworkSequenceNumber,
        data_size: u32,
    ) -> io::Result<()> {
        debug!(
            "Writing DataHeader stream_id={}, net_seq_num={}, data_size={}",
            stream_id.0, net_seq_num.0, data_size
        );
        w.write_u64(0).await?; // circuit_id unused
        w.write_u64(stream_id.0).await?;
        w.write_u64(net_seq_num.0).await?;
        w.write_u32(data_size).await?;
        w.write_u32(0).await?; // padding always zero
        Ok(())
    }
}

/// `struct lttcomm_relayd_generic_reply`
pub struct GenericResponse;

impl GenericResponse {
    #[allow(dead_code)]
    pub const WIRE_SIZE: usize = 4;

    pub async fn read<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<ErrorCode> {
        let ret_code = r.read_u32().await?;
        debug!("Read GenericResponse ret_code={}", ret_code);
        Ok(ErrorCode(ret_code))
    }
}

/// `struct lttcomm_relayd_version`
/// Response type: `Version`
pub struct Version;

impl Version {
    pub const WIRE_SIZE: usize = 4 + 4;

    pub async fn write<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        major: u32,
        minor: u32,
    ) -> io::Result<()> {
        debug!("Writing Version major={}, minor={}", major, minor);
        w.write_u32(major).await?;
        w.write_u32(minor).await?;
        Ok(())
    }

    pub async fn read<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<(u32, u32)> {
        let major = r.read_u32().await?;
        let minor = r.read_u32().await?;
        debug!("Read Version major={}, minor={}", major, minor);
        Ok((major, minor))
    }
}

#[derive(Debug, Error)]
pub enum CreateSessionError {
    #[error("Encountered an IO error while writing CreateSession command")]
    Io(#[from] io::Error),
    #[error(
        "Session name exceeds maximum length of {} bytes",
        CreateSession::NAME_MAX
    )]
    SessionNameLen,
    #[error(
        "Hostname name exceeds maximum length of {} bytes",
        CreateSession::HOST_NAME_MAX
    )]
    HostnameLen,
}

/// `struct lttcomm_relayd_create_session_2_4`
/// Response type: `CreateSessionResponse`
pub struct CreateSession;

impl CreateSession {
    /// RELAYD_COMM_LTTNG_NAME_MAX_2_4
    pub const NAME_MAX: usize = 255;
    /// RELAYD_COMM_LTTNG_HOST_NAME_MAX_2_4
    pub const HOST_NAME_MAX: usize = 64;

    pub const WIRE_SIZE: usize = Self::NAME_MAX + Self::HOST_NAME_MAX + 4 + 4;

    pub async fn write<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        session_name: &str,
        hostname: &str,
        live_timer: u32,
    ) -> Result<(), CreateSessionError> {
        debug!(
            "Writing CreateSession session_name='{}', hostname='{}', live_timer={}",
            session_name, hostname, live_timer
        );
        let session_name_bytes = session_name.as_bytes();
        let hostname_bytes = hostname.as_bytes();
        if session_name_bytes.len() >= Self::NAME_MAX {
            Err(CreateSessionError::SessionNameLen)
        } else if hostname_bytes.len() >= Self::HOST_NAME_MAX {
            Err(CreateSessionError::HostnameLen)
        } else {
            w.write_all(session_name_bytes).await?;
            let zero_padding = Self::NAME_MAX - session_name_bytes.len();
            for _ in 0..zero_padding {
                w.write_u8(0).await?;
            }
            w.write_all(hostname_bytes).await?;
            let zero_padding = Self::HOST_NAME_MAX - hostname_bytes.len();
            for _ in 0..zero_padding {
                w.write_u8(0).await?;
            }
            w.write_u32(live_timer).await?;
            w.write_u32(0).await?; // snapshot unused
            Ok(())
        }
    }
}

/// `struct lttcomm_relayd_status_session`
pub struct CreateSessionResponse;

impl CreateSessionResponse {
    #[allow(dead_code)]
    pub const WIRE_SIZE: usize = 8 + 4;

    pub async fn read<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<(SessionId, ErrorCode)> {
        let session_id = r.read_u64().await?;
        let ret_code = r.read_u32().await?;
        debug!(
            "Read CreateSessionResponse session_id={}, ret_code={}",
            session_id, ret_code
        );
        Ok((SessionId(session_id), ErrorCode(ret_code)))
    }
}

#[derive(Debug, Error)]
pub enum AddStreamError {
    #[error("Encountered an IO error while writing AddStream command")]
    Io(#[from] io::Error),
    #[error(
        "Channel name exceeds maximum length of {} bytes",
        AddStream::STREAM_NAME_MAX
    )]
    ChannelNameLen,
    #[error("Pathname exceeds maximum length of {} bytes", AddStream::PATH_MAX)]
    PathnameLen,
}

/// `struct lttcomm_relayd_add_stream_2_2`
/// Response type: `AddStreamResponse`
pub struct AddStream;

impl AddStream {
    /// RELAYD_COMM_DEFAULT_STREAM_NAME_LEN
    pub const STREAM_NAME_MAX: usize = 264;
    /// RELAYD_COMM_LTTNG_PATH_MAX
    pub const PATH_MAX: usize = 4096;

    pub const WIRE_SIZE: usize = Self::STREAM_NAME_MAX + Self::PATH_MAX + 8 + 8;

    pub async fn write<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        channel_name: &str,
        pathname: &str,
    ) -> Result<(), AddStreamError> {
        debug!(
            "Writing AddStream channel_name='{}', pathname='{}'",
            channel_name, pathname,
        );
        let channel_name_bytes = channel_name.as_bytes();
        let pathname_bytes = pathname.as_bytes();
        if channel_name_bytes.len() >= Self::STREAM_NAME_MAX {
            Err(AddStreamError::ChannelNameLen)
        } else if pathname_bytes.len() >= Self::PATH_MAX {
            Err(AddStreamError::PathnameLen)
        } else {
            w.write_all(channel_name_bytes).await?;
            let zero_padding = Self::STREAM_NAME_MAX - channel_name_bytes.len();
            for _ in 0..zero_padding {
                w.write_u8(0).await?;
            }
            w.write_all(pathname_bytes).await?;
            let zero_padding = Self::PATH_MAX - pathname_bytes.len();
            for _ in 0..zero_padding {
                w.write_u8(0).await?;
            }
            w.write_u64(0).await?; // tracefile_size unused
            w.write_u64(0).await?; // tracefile_count unused
            Ok(())
        }
    }
}

/// `struct lttcomm_relayd_status_stream`
pub struct AddStreamResponse;

impl AddStreamResponse {
    #[allow(dead_code)]
    pub const WIRE_SIZE: usize = 8 + 4;

    pub async fn read<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<(StreamId, ErrorCode)> {
        let stream_id = r.read_u64().await?;
        let ret_code = r.read_u32().await?;
        debug!(
            "Read AddStreamResponse stream_id={}, ret_code={}",
            stream_id, ret_code
        );
        Ok((StreamId(stream_id), ErrorCode(ret_code)))
    }
}

/// `struct lttcomm_relayd_close_stream`
/// Response type: `GenericResponse`
pub struct CloseStream;

impl CloseStream {
    pub const WIRE_SIZE: usize = 8 + 8;

    pub async fn write<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        stream_id: StreamId,
        last_net_seq_num: NetworkSequenceNumber,
    ) -> io::Result<()> {
        debug!(
            "Writing CloseStream stream_id={}, last_net_seq_num={}",
            stream_id.0, last_net_seq_num.0
        );
        w.write_u64(stream_id.0).await?;
        w.write_u64(last_net_seq_num.0).await?;
        Ok(())
    }
}

/// `struct lttcomm_relayd_metadata_payload`
/// Response type: None
pub struct SendMetadata;

impl SendMetadata {
    pub const fn wire_size(metadata_size: usize) -> usize {
        8 + 4 + metadata_size
    }

    pub async fn write<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        stream_id: StreamId,
        metadata: &[u8],
    ) -> io::Result<()> {
        debug!(
            "Writing SendMetadata stream_id={}, metadata_len={}",
            stream_id.0,
            metadata.len()
        );
        w.write_u64(stream_id.0).await?;
        w.write_u32(0).await?; // padding unused
        w.write_all(metadata).await?;
        Ok(())
    }
}

/// `struct lttcomm_relayd_index`
/// Response type: `GenericResponse`
pub struct SendIndex;

impl SendIndex {
    pub const WIRE_SIZE: usize = 8 * 10;

    pub async fn write<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        relay_stream_id: StreamId,
        net_seq_num: NetworkSequenceNumber,
        index: &Index,
    ) -> io::Result<()> {
        debug!(
            "Writing SendIndex relay_stream_id={}, net_seq_num={}",
            relay_stream_id.0, net_seq_num.0,
        );
        w.write_u64(relay_stream_id.0).await?;
        w.write_u64(net_seq_num.0).await?;
        w.write_u64(index.packet_size_bits.get()).await?;
        w.write_u64(index.content_size_bits).await?;
        w.write_u64(index.timestamp_begin).await?;
        w.write_u64(index.timestamp_end).await?;
        w.write_u64(index.events_discarded.0).await?;
        w.write_u64(index.stream_id).await?;
        w.write_u64(index.stream_instance_id.0).await?;
        w.write_u64(index.packet_seq_num.0).await?;
        Ok(())
    }
}
