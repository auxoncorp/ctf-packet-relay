use crate::packet::{CtfPacket, CtfPacketCodec, DecoderError};
use crate::serial::{self, DeviceOpts};
use crate::DeviceOrSocket;
use futures::stream::Stream;
use futures::stream::StreamExt;
use std::{
    collections::BTreeSet,
    io,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::codec::Decoder;
use tokio_util::udp::UdpFramed;
use tracing::{debug, info, warn};

pub struct PacketPublisherConfig {
    /// Packets with any of these stream IDs will
    /// be sent on the channel
    pub stream_ids: BTreeSet<u64>,
    /// The channel matching packets will be sent on
    pub sender: mpsc::Sender<CtfPacket>,
}

impl PacketPublisherConfig {
    fn sender(&self, stream_id: u64) -> Option<&mpsc::Sender<CtfPacket>> {
        // Empty set means all IDs are accepted on this channel
        if self.stream_ids.is_empty() || self.stream_ids.contains(&stream_id) {
            Some(&self.sender)
        } else {
            None
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Encountered end of stream unexpectedly")]
    EndOfStream,

    #[error("The packet receiver has shutdown")]
    ReceiverClosed,

    #[error("Socket setup problem. {0}")]
    SocketSetup(io::Error),
}

/// Value chosen "empirically" to reduce the odds of
/// dropping unprocessed frames on the floor
const SOCKET_RECV_BUF_SIZE: usize = 25_000_000;

pub async fn run_packet_publisher<P: AsRef<Path>>(
    source: DeviceOrSocket,
    device_opts: DeviceOpts,
    metadata_file: P,
    channel_configs: Vec<PacketPublisherConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut reader: Pin<Box<dyn Stream<Item = Result<CtfPacket, DecoderError>> + Send>> =
        match source {
            DeviceOrSocket::Device(d) => {
                let src = serial::open(&d, &device_opts)?;
                Box::pin(CtfPacketCodec::new(&metadata_file, &Default::default())?.framed(src))
            }
            DeviceOrSocket::UdpSocket(a) => {
                info!("Binding to {}", a);
                let socket = std::net::UdpSocket::bind(a).map_err(Error::SocketSetup)?;
                socket.set_nonblocking(true).map_err(Error::SocketSetup)?;
                // Switch into socket2 representation to fiddle with the recv_buffer_size,
                // which is not exposed in the standard `UdpSocket`
                let socket = socket2::Socket::from(socket);
                if let Ok(old_size) = socket.recv_buffer_size() {
                    if old_size < SOCKET_RECV_BUF_SIZE {
                        if let Err(e) = socket.set_recv_buffer_size(SOCKET_RECV_BUF_SIZE) {
                            warn!("Could not increase the UDP socket's recv buffer size to {}. Assume previously established size of {} remains. {}",
                      SOCKET_RECV_BUF_SIZE, old_size, e);
                        }
                    }
                } else if let Err(e) = socket.set_recv_buffer_size(SOCKET_RECV_BUF_SIZE) {
                    warn!(
                        "Could not set the UDP socket's recv buffer size to {}. {}",
                        SOCKET_RECV_BUF_SIZE, e
                    );
                }
                let socket = UdpSocket::from_std(socket.into()).map_err(Error::SocketSetup)?;
                Box::pin(UdpFramedWithoutSrcAddr {
                    s: UdpFramed::new(
                        socket,
                        CtfPacketCodec::new(&metadata_file, &Default::default())?,
                    ),
                })
            }
        };
    while let Some(pkt_result) = reader.next().await {
        let pkt = match pkt_result {
            Ok(p) => p,
            Err(e) => {
                warn!("Packet codec returned an error. {}", e);
                continue;
            }
        };
        debug!("{pkt}");

        if let Some(sender) = channel_configs
            .iter()
            .find_map(|c| c.sender(pkt.index.stream_id))
        {
            sender.send(pkt).await.map_err(|_| Error::ReceiverClosed)?;
        } else {
            debug!("Dropping packet because it has no receiver mapped");
        }
    }

    // This tasks never completes nor handles shutdowns
    Err(Error::EndOfStream.into())
}

pub struct UdpFramedWithoutSrcAddr {
    s: UdpFramed<CtfPacketCodec, UdpSocket>,
}

impl Unpin for UdpFramedWithoutSrcAddr {}

impl Stream for UdpFramedWithoutSrcAddr {
    type Item = Result<CtfPacket, DecoderError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();
        Stream::poll_next(Pin::new(&mut pin.s), cx).map_ok(|(t, _addr)| t)
    }
}
