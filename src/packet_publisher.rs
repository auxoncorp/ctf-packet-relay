use crate::packet::{CtfPacket, CtfPacketCodec};
use crate::serial::{self, DeviceOpts};
use futures::stream::StreamExt;
use std::collections::BTreeSet;
use std::path::Path;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::codec::Decoder;
use tracing::{debug, warn};

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
#[error("Encountered end of stream unexpectedly")]
pub struct EndOfStreamError;

#[derive(Debug, Error)]
#[error("The packet receiver has shutdown")]
pub struct ReceiverClosed;

pub async fn run_packet_publisher<P: AsRef<Path>>(
    device: String,
    device_opts: DeviceOpts,
    metadata_file: P,
    channel_configs: Vec<PacketPublisherConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dev = serial::open(&device, &device_opts)?;
    let mut reader = CtfPacketCodec::new(&metadata_file, &Default::default())?.framed(dev);
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
            sender.send(pkt).await.map_err(|_| ReceiverClosed)?;
        } else {
            debug!("Dropping packet because it has no receiver mapped");
        }
    }

    // This tasks never completes nor handles shutdowns
    Err(EndOfStreamError.into())
}
