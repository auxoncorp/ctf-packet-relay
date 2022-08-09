#![deny(warnings, clippy::all)]

use chrono::{DateTime, Utc};
use ctf_packet_relay::packet_publisher::{run_packet_publisher, PacketPublisherConfig};
use ctf_packet_relay::packet_subscriber::{run_packet_subscriber, PacketSubscriberConfig};
use ctf_packet_relay::serial::DeviceOpts;
use ctf_packet_relay::DeviceOrSocket;
use std::{collections::BTreeSet, fs, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use structopt::{clap, StructOpt};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error};

/// CTF packet relay
///
/// Relays CTF packets from a serial device or socket to one or more LTTng relayd sessions
#[derive(Debug, StructOpt)]
#[structopt(name = "ctf-packet-relay", verbatim_doc_comment)]
#[structopt(help_message = "Prints help information. Use --help for more details.")]
#[structopt(setting = clap::AppSettings::ColoredHelp)]
struct Opts {
    #[structopt(flatten)]
    device_opts: DeviceOpts,

    /// LTTng relayd control address:port
    #[structopt(short = "c", long, default_value = "127.0.0.1:5342")]
    control_port: SocketAddr,

    /// LTTng relayd trace data address:port
    #[structopt(short = "d", long, default_value = "127.0.0.1:5343")]
    data_port: SocketAddr,

    /// LTTng relayd hostname.
    /// The system hostname will be used if not provided.
    #[structopt(short = "H", long)]
    hostname: Option<String>,

    /// LTTng relayd live timer value.
    #[structopt(short = "t", long, name = "duration µs", default_value = "100000")]
    live_timer: u32,

    /// Map stream IDs to a specific LTTng relayd session name and pathname.
    ///
    /// This option can be supplied multiple times.
    ///
    /// The pathname portion can use the keyword $DATETIME as part of its
    /// value, which expands to UTC datetime in the format of YYYYmmdd-HHMMSS.
    ///
    /// The comma-separated-stream-ids can be set to ANY to match any stream ID.
    ///
    /// Format:
    ///   <session-name>:<pathname>:<comma-separated-stream-ids>
    ///
    /// Example:
    ///   --stream-mapping my-stream-a:trace-a:0,1
    ///   --stream-mapping my-stream-b:trace-b:2,5
    ///   --stream-mapping session-foo:session-$DATETIME:42
    #[structopt(name = "stream-mapping", short = "s", long, verbatim_doc_comment)]
    stream_mappings: Vec<StreamMapping>,

    /// CTF metadata file path
    #[structopt(name = "metadata-file")]
    metadata: PathBuf,

    /// Source serial device or socket URL
    ///
    /// Examples:
    /// - file:/dev/ttyUSB0
    /// - udp://localhost:456
    #[structopt(name = "device-or-socket", verbatim_doc_comment)]
    source_url: DeviceOrSocket,
}

#[derive(Debug, Error)]
enum HostnameError {
    #[error("The hostname '{0:?}' contains invalid data")]
    InvalidHostname(std::ffi::OsString),
    #[error("Encountered an IO error while retrieving the hostname")]
    Io(#[from] std::io::Error),
}

impl Opts {
    fn hostname(&self) -> Result<String, HostnameError> {
        if let Some(n) = &self.hostname {
            Ok(n.clone())
        } else {
            let n = hostname::get()?;
            Ok(n.into_string().map_err(HostnameError::InvalidHostname)?)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match do_main().await {
        Ok(()) => Ok(()),
        Err(e) => {
            error!("{}", e);
            Err(e)
        }
    }
}

async fn do_main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::from_args();

    try_init_tracing_subscriber()?;

    let intr = interruptor::Interruptor::new();
    ctrlc::set_handler(move || {
        if intr.is_set() {
            let exit_code = if cfg!(target_family = "unix") {
                // 128 (fatal error signal "n") + 2 (control-c is fatal error signal 2)
                130
            } else {
                // Windows code 3221225786
                // -1073741510 == C000013A
                -1073741510
            };
            std::process::exit(exit_code);
        } else {
            intr.set();
        }
    })?;

    let hostname = opts.hostname()?;
    let md_bytes = Arc::new(fs::read_to_string(&opts.metadata)?.into_bytes());

    let stream_mappings = if !opts.stream_mappings.is_empty() {
        opts.stream_mappings
    } else {
        vec![StreamMapping::default()]
    };

    // Check that there are no overlapping stream IDs among the stream mappings, must be exclusive
    // Same for duplicate session names
    let mut all_stream_ids = BTreeSet::new();
    let mut all_session_names = BTreeSet::new();
    for smap in stream_mappings.iter() {
        for id in smap.stream_ids.iter() {
            if !all_stream_ids.insert(*id) {
                return Err(DuplicateStreamIdMappingError(smap.session_name.clone(), *id).into());
            }
        }

        if !all_session_names.insert(&smap.session_name) {
            return Err(DuplicateSessionNameMappingError(smap.session_name.clone()).into());
        }
    }

    let (shutdown_req_sender, shutdown_req_recvr) = broadcast::channel(1);
    let (shutdown_resp_sender, mut shutdown_resp_recvr) = mpsc::channel(1);

    let mut pkt_pub_cfgs = Vec::new();
    let mut pkt_sub_cfgs = Vec::new();
    for s in stream_mappings.into_iter() {
        let (pkt_pub_sender, pkt_pub_recvr) = mpsc::channel(64);

        pkt_pub_cfgs.push(PacketPublisherConfig {
            stream_ids: s.stream_ids,
            sender: pkt_pub_sender,
        });

        pkt_sub_cfgs.push(PacketSubscriberConfig {
            control_port: opts.control_port,
            data_port: opts.data_port,
            hostname: hostname.clone(),
            session_name: s.session_name,
            pathname: s.pathname,
            live_timer: opts.live_timer,
            metadata_bytes: md_bytes.clone(),
            packet_receiver: pkt_pub_recvr,
            shutdown_receiver: shutdown_req_sender.subscribe(),
            shutdown_responder: shutdown_resp_sender.clone(),
        })
    }

    let mut pkt_subs_join_handle = tokio::spawn(async move {
        futures::future::try_join_all(pkt_sub_cfgs.into_iter().map(run_packet_subscriber)).await
    });

    let mut pkt_pub_join_handle = tokio::spawn(async move {
        run_packet_publisher(
            opts.source_url.clone(),
            opts.device_opts.clone(),
            opts.metadata.clone(),
            pkt_pub_cfgs,
        )
        .await
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            debug!("User signaled shutdown");
        }
        res = &mut pkt_pub_join_handle => {
            debug!("Packet publisher returned unexpectedly");
            match res? {
                Ok(_) => {},
                Err(e) => return Err(e),
            }
        }
        res = &mut pkt_subs_join_handle => {
            debug!("Packet subscriber returned unexpectedly");
            match res? {
                Ok(_) => {},
                Err(e) => return Err(e),
            }
        }
    };

    drop(shutdown_req_recvr);
    drop(shutdown_resp_sender);
    shutdown_req_sender.send(())?;
    let _ = shutdown_resp_recvr.recv().await;

    Ok(())
}

fn try_init_tracing_subscriber() -> Result<(), Box<dyn std::error::Error>> {
    let builder = tracing_subscriber::fmt::Subscriber::builder();
    let env_filter = std::env::var(tracing_subscriber::EnvFilter::DEFAULT_ENV)
        .map(tracing_subscriber::EnvFilter::new)
        .unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new(format!(
                "{}={}",
                env!("CARGO_PKG_NAME").replace('-', "_"),
                tracing::Level::WARN
            ))
        });
    let builder = builder.with_env_filter(env_filter);
    let subscriber = builder.finish();
    use tracing_subscriber::util::SubscriberInitExt;
    subscriber.try_init()?;
    Ok(())
}

mod interruptor {
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    #[repr(transparent)]
    pub struct Interruptor(Arc<AtomicBool>);

    impl Interruptor {
        pub fn new() -> Self {
            Interruptor(Arc::new(AtomicBool::new(false)))
        }

        pub fn set(&self) {
            self.0.store(true, SeqCst);
        }

        pub fn is_set(&self) -> bool {
            self.0.load(SeqCst)
        }
    }

    impl Default for Interruptor {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[derive(Debug, Error)]
#[error("Stream mapping for session '{0}' contains a stream ID ({1}) that is already mapped to another stream")]
pub struct DuplicateStreamIdMappingError(String, u64);

#[derive(Debug, Error)]
#[error("The session name '{0}' can only be used in a single stream mapping")]
pub struct DuplicateSessionNameMappingError(String);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct StreamMapping {
    /// Defaults to 'session'
    pub session_name: String,
    /// Defaults to 'trace'
    pub pathname: String,
    /// Defaults to empty, meaning all stream IDs
    pub stream_ids: BTreeSet<u64>,
}

impl Default for StreamMapping {
    fn default() -> Self {
        Self {
            session_name: "session".to_string(),
            pathname: "trace".to_string(),
            stream_ids: Default::default(),
        }
    }
}

impl FromStr for StreamMapping {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err_msg =
            "Invalid stream mapping format, use <session-name>:<pathname>:<comma-separated-stream-ids>";
        let parts: Vec<&str> = s.trim().split(':').filter(|s| !s.is_empty()).collect();
        if parts.len() != 3 {
            return Err(err_msg.to_string());
        }
        let session_name = parts[0].to_string();
        let pathname_str = parts[1];
        let ids = parts[2];

        let pathname = if pathname_str.contains("$DATETIME") {
            let now: DateTime<Utc> = Utc::now();
            let datetime = now.format("%Y%m%d-%H%M%S").to_string();
            pathname_str.replace("$DATETIME", &datetime)
        } else {
            pathname_str.to_string()
        };

        Ok(Self {
            session_name,
            pathname,
            stream_ids: if ids == "ANY" {
                Default::default()
            } else {
                ids.split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.trim().parse::<u64>())
                    .collect::<Result<BTreeSet<u64>, _>>()
                    .map_err(|_| err_msg.to_string())?
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn stream_mappings() {
        assert_eq!(
            StreamMapping::from_str("my-stream-a:trace-a:0,1,22,44").unwrap(),
            StreamMapping {
                session_name: "my-stream-a".to_owned(),
                pathname: "trace-a".to_owned(),
                stream_ids: vec![0, 1, 22, 44].into_iter().collect(),
            }
        );

        assert_eq!(
            StreamMapping::from_str("my-stream-a:trace-a:ANY").unwrap(),
            StreamMapping {
                session_name: "my-stream-a".to_owned(),
                pathname: "trace-a".to_owned(),
                stream_ids: Default::default(),
            }
        );

        let sm = StreamMapping::from_str("system-session:system=$DATETIME:1, 2, 4").unwrap();
        assert_eq!(sm.session_name, "system-session".to_owned());
        assert_eq!(sm.stream_ids, vec![1, 2, 4].into_iter().collect());
        let parts: Vec<&str> = sm.pathname.split('=').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "system");
        assert!(Utc.datetime_from_str(parts[1], "%Y%m%d-%H%M%S").is_ok());
    }
}
