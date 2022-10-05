use derive_more::{From, Into};
use std::path::Path;
use std::str::FromStr;
use structopt::{clap, StructOpt};
use thiserror::Error;
use tokio_serial::{ClearBuffer, SerialPort, SerialPortBuilderExt, SerialStream};
use tracing::info;

#[derive(Debug, Error)]
pub enum Error {
    #[error("The serial device '{0}' doesn't exist")]
    NonExistingDevice(String),

    #[error("Serial device error")]
    Serial(#[from] tokio_serial::Error),
}

pub fn open(device: &str, opts: &DeviceOpts) -> Result<SerialStream, Error> {
    info!(
        "Opening '{}', baud_rate={}, data_bits={:?}, parity={:?}, stop_bits={:?}",
        device, opts.baud_rate, opts.data_bits.0, opts.parity.0, opts.stop_bits.0
    );

    if !Path::new(device).exists() {
        return Err(Error::NonExistingDevice(device.to_string()));
    }

    let mut port = tokio_serial::new(device, opts.baud_rate)
        .data_bits(opts.data_bits.0)
        .flow_control(opts.flow_control.0)
        .parity(opts.parity.0)
        .stop_bits(opts.stop_bits.0)
        .open_native_async()?;
    port.clear(ClearBuffer::All)?;

    #[cfg(unix)]
    port.set_exclusive(false)?;

    Ok(port)
}

#[derive(Debug, Clone, PartialEq, Eq, StructOpt)]
#[structopt(setting = clap::AppSettings::ColoredHelp)]
pub struct DeviceOpts {
    /// Serial device baud rate
    #[structopt(short = "b", long, default_value = "115200")]
    pub baud_rate: u32,

    /// Serial device data bits
    #[structopt(long, default_value = "8")]
    pub data_bits: DataBits,

    /// Serial device flow control
    #[structopt(long, default_value = "none")]
    pub flow_control: FlowControl,

    /// Serial device parity checking mode.
    #[structopt(long, default_value = "none")]
    pub parity: Parity,

    /// Serial device stop bits
    #[structopt(long, default_value = "1")]
    pub stop_bits: StopBits,
}

impl Default for DeviceOpts {
    fn default() -> Self {
        Self {
            baud_rate: 115200,
            data_bits: tokio_serial::DataBits::Eight.into(),
            flow_control: tokio_serial::FlowControl::None.into(),
            parity: tokio_serial::Parity::None.into(),
            stop_bits: tokio_serial::StopBits::One.into(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Into)]
pub struct DataBits(pub tokio_serial::DataBits);

impl FromStr for DataBits {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(match s.trim().to_lowercase().as_str() {
            "5" | "five" => tokio_serial::DataBits::Five,
            "6" | "six" => tokio_serial::DataBits::Six,
            "7" | "seven" => tokio_serial::DataBits::Seven,
            "8" | "eight" => tokio_serial::DataBits::Eight,
            _ => return Err("Invalid data bits".to_string()),
        }))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Into)]
pub struct FlowControl(pub tokio_serial::FlowControl);

impl FromStr for FlowControl {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(match s.trim().to_lowercase().as_str() {
            "none" => tokio_serial::FlowControl::None,
            "software" | "sw" => tokio_serial::FlowControl::Software,
            "hardware" | "hw" => tokio_serial::FlowControl::Hardware,
            _ => return Err("Invalid flow control".to_string()),
        }))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Into)]
pub struct Parity(pub tokio_serial::Parity);

impl FromStr for Parity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(match s.trim().to_lowercase().as_str() {
            "none" => tokio_serial::Parity::None,
            "odd" => tokio_serial::Parity::Odd,
            "even" => tokio_serial::Parity::Even,
            _ => return Err("Invalid parity".to_string()),
        }))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Into)]
pub struct StopBits(pub tokio_serial::StopBits);

impl FromStr for StopBits {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(match s.trim().to_lowercase().as_str() {
            "1" | "one" => tokio_serial::StopBits::One,
            "2" | "two" => tokio_serial::StopBits::Two,
            _ => return Err("Invalid stop bits".to_string()),
        }))
    }
}
