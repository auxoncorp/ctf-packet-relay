#![deny(warnings, clippy::all)]

use std::net::SocketAddr;
use std::str::FromStr;
use url::Url;

pub mod packet;
pub mod packet_publisher;
pub mod packet_subscriber;
pub mod relayd;
pub mod serial;

#[derive(Debug, Clone)]
pub enum DeviceOrSocket {
    Device(String),
    UdpSocket(SocketAddr),
}

impl FromStr for DeviceOrSocket {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).map_err(|e| format!("Failed to parse source URL. {}", e))?;
        Ok(match url.scheme() {
            "file" => DeviceOrSocket::Device(url.path().to_string()),
            "udp" => {
                let addrs = url
                    .socket_addrs(|| None)
                    .map_err(|e| format!("Failed to parse source URL. {}", e))?;
                if addrs.len() != 1 {
                    return Err("Source URL contains multiple socket addresses.".to_string());
                }
                DeviceOrSocket::UdpSocket(addrs[0])
            }
            s => {
                return Err(format!(
                    "Invalid scheme '{}' in source URL. Must be either 'file' or 'udp'.",
                    s
                ))
            }
        })
    }
}
