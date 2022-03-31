use crate::packet::{CtfPacket, CtfPacketMagic};
use crate::relayd::wire::Index;
use babeltrace2_sys::internal_api::{PacketDecoder, PacketDecoderConfig, PacketProperties};
use babeltrace2_sys::Error;
use bytes::{Bytes, BytesMut};
use std::io;
use std::num::NonZeroU64;
use std::path::Path;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum DecoderError {
    #[error("{0}")]
    Babeltrace(#[from] Error),

    #[error("Encountered in IO error while reading. {0}")]
    Io(#[from] io::Error),
}

pub struct CtfPacketCodec {
    dec: PacketDecoder,
}

// PacketDecoder has raw pointers, but it's all reentrant
unsafe impl Send for CtfPacketCodec {}

impl CtfPacketCodec {
    pub fn new<P: AsRef<Path>>(
        metadata_path: P,
        config: &PacketDecoderConfig,
    ) -> Result<Self, DecoderError> {
        let dec = PacketDecoder::new(metadata_path, config)?;
        Ok(Self { dec })
    }
}

impl Decoder for CtfPacketCodec {
    type Item = CtfPacket;
    type Error = DecoderError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Find start of packet if we can
        let mut found_magic = false;
        for idx in 0..src.len() {
            if CtfPacketMagic::check_magic(&src[idx..]) {
                debug!("Found magic at offset {idx}, len={}", src.len());
                if idx != 0 {
                    let mut junk = src.split_to(idx);
                    junk.clear();
                }
                found_magic = true;
                break;
            }
        }

        if !found_magic {
            return Ok(None);
        }

        match self.dec.packet_properties(src) {
            Err(_) => {
                // Assume this is because not enough bytes to parse full packet header
                // since we've got a magic already
                Ok(None)
            }
            Ok(None) => Ok(None),
            Ok(Some(p)) => Ok(props_to_packet(&p, src)),
        }
    }
}

fn props_to_packet(p: &PacketProperties, src: &mut BytesMut) -> Option<CtfPacket> {
    props_to_index(p, src).map(|(index, packet)| CtfPacket { index, packet })
}

fn props_to_index(p: &PacketProperties, src: &mut BytesMut) -> Option<(Index, Bytes)> {
    let (packet_total_size_bits, packet_total_size_bytes) = match pkt_size(p) {
        Some((bits, bytes)) => (bits, bytes),
        None => {
            // Got a header without 'packet_size', have to drop all the bytes we've got
            warn!("Dropping {} bytes", src.len(),);
            src.clear();
            return None;
        }
    };

    // We've got enough bytes for the packet header,
    // but not the whole packet yet, wait for more bytes
    // before doing other checks
    if packet_total_size_bytes > src.len() {
        return None;
    }

    // lttng relayd indices require certain packet header fields to exist
    let fields = match get_required_fields(p) {
        Some(f) => f,
        None => {
            warn!(
                "The packet is missing required fields, dropping {} bytes",
                packet_total_size_bytes
            );
            let _dropped = src.split_to(packet_total_size_bytes);
            return None;
        }
    };

    let pkt_bytes = src.split_to(packet_total_size_bytes).freeze();

    Some((
        Index {
            packet_size_bits: packet_total_size_bits,
            content_size_bits: fields.packet_content_size_bits,
            timestamp_begin: fields.timestamp_begin,
            timestamp_end: fields.timestamp_end,
            events_discarded: p.discarded_events.into(),
            stream_id: fields.stream_id,
            stream_instance_id: p.data_stream_id.into(),
            packet_seq_num: p.packet_seq_num.into(),
        },
        pkt_bytes,
    ))
}

fn get_required_fields(p: &PacketProperties) -> Option<RequiredFields> {
    Some(RequiredFields {
        packet_content_size_bits: content_size(p)?,
        timestamp_begin: timestamp_begin(p)?,
        timestamp_end: timestamp_end(p)?,
        stream_id: stream_id(p)?,
    })
}

struct RequiredFields {
    packet_content_size_bits: u64,
    timestamp_begin: u64,
    timestamp_end: u64,
    stream_id: u64,
}

fn pkt_size(p: &PacketProperties) -> Option<(NonZeroU64, usize)> {
    if let Some(size_bits) = p.packet_total_size_bits {
        match NonZeroU64::new(size_bits) {
            Some(s) => Some((s, s.get() as usize >> 3)),
            None => {
                warn!("Packet field 'packet_size' cannot be zero");
                None
            }
        }
    } else {
        warn!("Packet is missing 'packet_size' field");
        None
    }
}

fn content_size(p: &PacketProperties) -> Option<u64> {
    if let Some(size_bits) = p.packet_content_size_bits {
        size_bits.into()
    } else {
        warn!("Packet is missing 'content_size' field");
        None
    }
}

fn timestamp_begin(p: &PacketProperties) -> Option<u64> {
    if let Some(t) = p.beginning_clock {
        t.into()
    } else {
        warn!("Packet is missing 'timestamp_begin' field");
        None
    }
}

fn timestamp_end(p: &PacketProperties) -> Option<u64> {
    if let Some(t) = p.end_clock {
        t.into()
    } else {
        warn!("Packet is missing 'timestamp_end' field");
        None
    }
}

fn stream_id(p: &PacketProperties) -> Option<u64> {
    if let Some(id) = p.stream_class_id {
        id.into()
    } else {
        warn!("Packet is missing stream 'id' field");
        None
    }
}

impl Encoder<String> for CtfPacketCodec {
    type Error = io::Error;

    fn encode(&mut self, _item: String, _dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Encoding not implemented
        Ok(())
    }
}
