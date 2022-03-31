use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{debug, info};
use wire::*;

pub(crate) mod wire;

#[derive(Debug, Error)]
pub enum RelaydClientError {
    #[error("Control socket setup error")]
    ControlSocketSetup(io::Error),

    #[error("Data socket setup error")]
    DataSocketSetup(io::Error),

    #[error("Failed to create a new lttng-relayd session")]
    CreateSession(#[from] CreateSessionError),

    #[error("Failed to add a new lttng-relayd stream")]
    AddStream(#[from] AddStreamError),

    #[error(transparent)]
    LttngRelayd(#[from] LttngRelaydError),

    #[error("Invalid stream id ({0})")]
    InvalidStreamId(StreamId),

    #[error("IO error")]
    Io(#[from] io::Error),
}

pub struct RelaydClient<S: RelaydClientState> {
    state: S,
    common: CommonState,
}

pub struct ConnectedState {}
pub struct ActiveSessionState {
    session_id: SessionId,
}
pub struct StreamableState {
    session_id: SessionId,
    pathname: Arc<String>,
    metadata_stream: StreamId,
    data_streams: BTreeMap<StreamId, NetworkSequenceNumber>,
}

struct CommonState {
    control_stream: TcpStream,
    data_stream: TcpStream,
    buffer: Vec<u8>,
}

/// 8K buffer sufficient for all our control plane messaging
const CONTROL_BUFFER_SIZE: usize = 4096 * 2;

impl RelaydClient<ConnectedState> {
    pub async fn new(
        control_port: &SocketAddr,
        data_port: &SocketAddr,
    ) -> Result<RelaydClient<ConnectedState>, RelaydClientError> {
        debug!("Connecting to lttng-relayd control port {}", control_port);
        let control_stream = TcpStream::connect(control_port)
            .await
            .map_err(RelaydClientError::ControlSocketSetup)?;
        debug!("Connecting to lttng-relayd data port {}", data_port);
        let data_stream = TcpStream::connect(data_port)
            .await
            .map_err(RelaydClientError::DataSocketSetup)?;

        Ok(Self {
            state: ConnectedState {},
            common: CommonState {
                control_stream,
                data_stream,
                buffer: Vec::with_capacity(CONTROL_BUFFER_SIZE),
            },
        })
    }

    pub async fn create_session(
        mut self,
        session_name: &str,
        hostname: &str,
        live_timer: u32,
    ) -> Result<RelaydClient<ActiveSessionState>, RelaydClientError> {
        info!("Creating '{}/{}' session", hostname, session_name);
        self.do_version_handshake().await?;
        let session_id = self
            .create_new_session(session_name, hostname, live_timer)
            .await?;
        Ok(RelaydClient {
            state: ActiveSessionState { session_id },
            common: self.common,
        })
    }

    async fn do_version_handshake(&mut self) -> Result<(), RelaydClientError> {
        self.common.buffer.clear();
        ControlHeader::write(
            &mut self.common.buffer,
            Command::Version,
            Version::WIRE_SIZE as _,
        )
        .await?;
        Version::write(&mut self.common.buffer, VERSION_MAJOR, VERSION_MINOR).await?;
        self.write_control_buffer().await?;
        self.common.control_stream.readable().await?;
        let (_major, _minor) = Version::read(&mut self.common.control_stream).await?;
        Ok(())
    }

    async fn create_new_session(
        &mut self,
        session_name: &str,
        hostname: &str,
        live_timer: u32,
    ) -> Result<SessionId, RelaydClientError> {
        self.common.buffer.clear();
        ControlHeader::write(
            &mut self.common.buffer,
            Command::CreateSession,
            CreateSession::WIRE_SIZE as _,
        )
        .await?;
        CreateSession::write(&mut self.common.buffer, session_name, hostname, live_timer).await?;
        self.write_control_buffer().await?;
        self.common.control_stream.readable().await?;
        let (session_id, ret_code) =
            CreateSessionResponse::read(&mut self.common.control_stream).await?;
        ret_code.check()?;
        Ok(session_id)
    }
}

impl RelaydClient<ActiveSessionState> {
    pub async fn start(
        mut self,
        pathname: &str,
        metadata_bytes: &[u8],
    ) -> Result<RelaydClient<StreamableState>, RelaydClientError> {
        info!(
            "Starting session, streams will be written into the '{}' directory",
            pathname
        );
        let metadata_stream = self.add_stream("metadata", pathname).await?;
        self.send_metadata(metadata_stream, metadata_bytes).await?;
        self.send_start_data().await?;
        Ok(RelaydClient {
            state: StreamableState {
                session_id: self.state.session_id,
                pathname: Arc::new(pathname.to_string()),
                metadata_stream,
                data_streams: Default::default(),
            },
            common: self.common,
        })
    }

    async fn send_metadata(
        &mut self,
        stream_id: StreamId,
        metadata_bytes: &[u8],
    ) -> Result<(), RelaydClientError> {
        self.common.buffer.clear();
        ControlHeader::write(
            &mut self.common.buffer,
            Command::SendMetadata,
            SendMetadata::wire_size(metadata_bytes.len()) as _,
        )
        .await?;
        self.common
            .buffer
            .reserve(SendMetadata::wire_size(metadata_bytes.len()));
        SendMetadata::write(&mut self.common.buffer, stream_id, metadata_bytes).await?;
        self.write_control_buffer().await?;
        Ok(())
    }

    async fn send_start_data(&mut self) -> Result<(), RelaydClientError> {
        self.common.buffer.clear();
        ControlHeader::write(&mut self.common.buffer, Command::StartData, 0).await?;
        self.write_control_buffer().await?;
        self.common.control_stream.readable().await?;
        let ret_code = GenericResponse::read(&mut self.common.control_stream).await?;
        ret_code.check()?;
        Ok(())
    }
}

impl RelaydClient<StreamableState> {
    pub async fn close_streams(
        self,
    ) -> Result<RelaydClient<ActiveSessionState>, RelaydClientError> {
        let StreamableState {
            session_id,
            pathname: _,
            metadata_stream,
            data_streams,
        } = self.state;

        let mut new_client = RelaydClient {
            state: ActiveSessionState { session_id },
            common: self.common,
        };

        // Close all the data streams first
        for (stream_id, net_seq_num) in data_streams.into_iter() {
            // Send the last net_seq_num sent
            let last_net_seq_num = net_seq_num.previous();
            new_client.close_stream(stream_id, last_net_seq_num).await?;
        }

        // Close the metadata stream
        // metadata was *not* packetized, so no seq num
        new_client
            .close_stream(metadata_stream, NetworkSequenceNumber::NONE)
            .await?;

        Ok(new_client)
    }

    pub async fn add_data_stream(
        &mut self,
        stream_class_id: u64,
    ) -> Result<StreamId, RelaydClientError> {
        let stream_filename = format!("stream{}", stream_class_id);
        let pathname = self.state.pathname.clone();
        let stream_id = self.add_stream(&stream_filename, &pathname).await?;
        self.state
            .data_streams
            .insert(stream_id, NetworkSequenceNumber::default());
        // Inform relayd we've got a new stream
        self.send_streams_sent().await?;
        Ok(stream_id)
    }

    pub async fn send_indexed_data(
        &mut self,
        stream_id: StreamId,
        index: &Index,
        data: &[u8],
    ) -> Result<(), RelaydClientError> {
        let net_seq_num = self
            .state
            .data_streams
            .get(&stream_id)
            .cloned()
            .ok_or(RelaydClientError::InvalidStreamId(stream_id))?;
        self.send_data(stream_id, net_seq_num, data).await?;
        self.send_index(stream_id, net_seq_num, index).await?;
        if let Some(nsn) = self.state.data_streams.get_mut(&stream_id) {
            nsn.increment();
        }
        Ok(())
    }

    async fn send_data(
        &mut self,
        stream_id: StreamId,
        net_seq_num: NetworkSequenceNumber,
        data: &[u8],
    ) -> Result<(), RelaydClientError> {
        self.common.buffer.clear();
        DataHeader::write(
            &mut self.common.buffer,
            stream_id,
            net_seq_num,
            data.len() as _,
        )
        .await?;
        self.common.data_stream.writable().await?;
        self.common
            .data_stream
            .write_all(&self.common.buffer)
            .await?;
        self.common.data_stream.writable().await?;
        self.common.data_stream.write_all(data).await?;
        Ok(())
    }

    async fn send_index(
        &mut self,
        stream_id: StreamId,
        net_seq_num: NetworkSequenceNumber,
        index: &Index,
    ) -> Result<(), RelaydClientError> {
        self.common.buffer.clear();
        ControlHeader::write(
            &mut self.common.buffer,
            Command::SendIndex,
            SendIndex::WIRE_SIZE as _,
        )
        .await?;
        SendIndex::write(&mut self.common.buffer, stream_id, net_seq_num, index).await?;
        self.write_control_buffer().await?;
        self.common.control_stream.readable().await?;
        let ret_code = GenericResponse::read(&mut self.common.control_stream).await?;
        ret_code.check()?;
        Ok(())
    }
}

impl<S: RelaydClientState> RelaydClient<S> {
    async fn write_control_buffer(&mut self) -> Result<(), RelaydClientError> {
        self.common.control_stream.writable().await?;
        self.common
            .control_stream
            .write_all(&self.common.buffer)
            .await?;
        Ok(())
    }

    async fn add_stream(
        &mut self,
        channel_name: &str,
        pathname: &str,
    ) -> Result<StreamId, RelaydClientError> {
        self.common.buffer.clear();
        ControlHeader::write(
            &mut self.common.buffer,
            Command::AddStream,
            AddStream::WIRE_SIZE as _,
        )
        .await?;
        AddStream::write(&mut self.common.buffer, channel_name, pathname).await?;
        self.write_control_buffer().await?;
        self.common.control_stream.readable().await?;
        let (stream_id, ret_code) =
            AddStreamResponse::read(&mut self.common.control_stream).await?;
        ret_code.check()?;
        Ok(stream_id)
    }

    async fn send_streams_sent(&mut self) -> Result<(), RelaydClientError> {
        self.common.buffer.clear();
        ControlHeader::write(&mut self.common.buffer, Command::StreamsSent, 0).await?;
        self.write_control_buffer().await?;
        self.common.control_stream.readable().await?;
        let ret_code = GenericResponse::read(&mut self.common.control_stream).await?;
        ret_code.check()?;
        Ok(())
    }

    async fn close_stream(
        &mut self,
        stream_id: StreamId,
        last_net_seq_num: NetworkSequenceNumber,
    ) -> Result<(), RelaydClientError> {
        self.common.buffer.clear();
        ControlHeader::write(
            &mut self.common.buffer,
            Command::CloseStream,
            CloseStream::WIRE_SIZE as _,
        )
        .await?;
        CloseStream::write(&mut self.common.buffer, stream_id, last_net_seq_num).await?;
        self.write_control_buffer().await?;
        self.common.control_stream.readable().await?;
        let ret_code = GenericResponse::read(&mut self.common.control_stream).await?;
        ret_code.check()?;
        Ok(())
    }
}

pub trait RelaydClientState: private::Sealed {}

impl RelaydClientState for ConnectedState {}
impl RelaydClientState for ActiveSessionState {}
impl RelaydClientState for StreamableState {}

mod private {
    pub trait Sealed {}

    impl Sealed for super::ConnectedState {}
    impl Sealed for super::ActiveSessionState {}
    impl Sealed for super::StreamableState {}
}
