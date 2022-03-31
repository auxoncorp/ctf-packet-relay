use crate::packet::CtfPacket;
use crate::relayd::RelaydClient;
use std::collections::{btree_map::Entry, BTreeMap};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

pub struct PacketSubscriberConfig {
    pub control_port: SocketAddr,
    pub data_port: SocketAddr,
    pub hostname: String,
    pub session_name: String,
    pub pathname: String,
    pub live_timer: u32,
    pub metadata_bytes: Arc<Vec<u8>>,
    pub packet_receiver: mpsc::Receiver<CtfPacket>,
    pub shutdown_receiver: broadcast::Receiver<()>,
    pub shutdown_responder: mpsc::Sender<()>,
}

pub async fn run_packet_subscriber(
    cfg: PacketSubscriberConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let PacketSubscriberConfig {
        control_port,
        data_port,
        hostname,
        session_name,
        pathname,
        live_timer,
        metadata_bytes,
        mut packet_receiver,
        mut shutdown_receiver,
        shutdown_responder: _,
    } = cfg;

    let client = RelaydClient::new(&control_port, &data_port).await?;
    let client = client
        .create_session(&session_name, &hostname, live_timer)
        .await?;
    let mut client = client.start(&pathname, &metadata_bytes).await?;

    let mut stream_class_ids_to_stream_ids = BTreeMap::new();

    loop {
        let pkt = tokio::select! {
            _ = shutdown_receiver.recv() => {
                debug!("Shutting down");
                let _client = client.close_streams().await?;
                return Ok(())
            }
            maybe_pkt = packet_receiver.recv() => match maybe_pkt {
                Some(pkt) => pkt,
                None => {
                warn!("Shutting down unexpectedly");
                let _client = client.close_streams().await?;
                return Ok(())
                }
            }
        };

        let stream_id = match stream_class_ids_to_stream_ids.entry(pkt.index.stream_id) {
            Entry::Vacant(entry) => {
                let stream_id = client.add_data_stream(pkt.index.stream_id).await?;
                entry.insert(stream_id);
                stream_id
            }
            Entry::Occupied(entry) => *entry.get(),
        };

        client
            .send_indexed_data(stream_id, &pkt.index, &pkt.packet)
            .await?;
    }
}
