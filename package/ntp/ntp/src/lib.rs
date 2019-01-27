use genet_derive::{Attr, Package};
use genet_sdk::{decoder::*, prelude::*};

struct NtpWorker {
    layer: LayerType<Ntp>,
}

impl Worker for NtpWorker {
    fn decode(&mut self, stack: &mut LayerStack) -> Result<Status> {
        let parent_src: u16 = stack
            .top()
            .unwrap()
            .attr(token!("udp.src"))
            .unwrap()
            .get()?
            .try_into()?;

        let parent_dst: u16 = stack
            .top()
            .unwrap()
            .attr(token!("udp.dst"))
            .unwrap()
            .get()?
            .try_into()?;

        if parent_src != 123 && parent_dst != 123 {
            return Ok(Status::Skip);
        }

        let data = stack.top().unwrap().payload();
        let mut layer = Layer::new(&self.layer, &data);

        let stratum = self.layer.stratum.get(&layer)?;
        let class = if stratum >= 2 {
            &self.layer.identifier_ip
        } else {
            &self.layer.identifier
        };
        layer.add_attr(&class, class.byte_range());

        stack.add_child(layer);
        Ok(Status::Done)
    }
}

#[derive(Default, Clone)]
struct NtpDecoder {}

impl Decoder for NtpDecoder {
    fn new_worker(&self, _ctx: &Context) -> Result<Box<Worker>> {
        Ok(Box::new(NtpWorker {
            layer: LayerType::new("ntp"),
        }))
    }
}

#[derive(Attr)]
struct Ntp {
    #[attr(bit_size = 2, map = "x >> 6")]
    leap_indicator: Enum<u8, Leap>,

    #[attr(bit_size = 3, map = "(x >> 3) & 0b111")]
    version: u8,

    #[attr(bit_size = 3, map = "x & 0b111")]
    mode: Enum<u8, Mode>,

    stratum: Node<u8>,

    poll_interval: u8,

    precision: u8,

    #[attr(map = "(x >> 16) as f64 + ((x & 0xffff) as f64 / 65536f64)")]
    root_delay: Node<Cast<u32, f64>, ShortFormat>,

    #[attr(map = "(x >> 16) as f64 + ((x & 0xffff) as f64 / 65536f64)")]
    root_dispersion: Node<Cast<u32, f64>, ShortFormat>,

    #[attr(skip, byte_size = 4)]
    identifier: Node<Bytes>,

    #[attr(
        skip,
        align_before,
        id = "identifier",
        byte_size = 4,
        typ = "@ipv4:addr"
    )]
    identifier_ip: Node<Bytes>,

    #[attr(
        typ = "@ntp:time",
        map = "(x >> 32) as f64 + ((x & 0xffff_ffff) as f64 / 4294967296f64)"
    )]
    reference_ts: Node<Cast<u64, f64>, TimeFormat>,

    #[attr(
        typ = "@ntp:time",
        map = "(x >> 32) as f64 + ((x & 0xffff_ffff) as f64 / 4294967296f64)"
    )]
    originate_ts: Node<Cast<u64, f64>, TimeFormat>,

    #[attr(
        typ = "@ntp:time",
        map = "(x >> 32) as f64 + ((x & 0xffff_ffff) as f64 / 4294967296f64)"
    )]
    receive_ts: Node<Cast<u64, f64>, TimeFormat>,

    #[attr(
        typ = "@ntp:time",
        map = "(x >> 32) as f64 + ((x & 0xffff_ffff) as f64 / 4294967296f64)"
    )]
    transmit_ts: Node<Cast<u64, f64>, TimeFormat>,
}

#[derive(Attr)]
struct ShortFormat {
    seconds: u16,
    fraction: u16,
}

#[derive(Attr)]
struct TimeFormat {
    seconds: u32,
    fraction: u32,
}

#[derive(Attr)]
enum Leap {
    NoWarning,
    Sec61,
    Sec59,
    Unknown,
}

impl Default for Leap {
    fn default() -> Self {
        Leap::Unknown
    }
}

impl From<u8> for Leap {
    fn from(data: u8) -> Self {
        match data {
            0 => Leap::NoWarning,
            1 => Leap::Sec61,
            2 => Leap::Sec59,
            _ => Self::default(),
        }
    }
}

#[derive(Attr)]
enum Mode {
    Reserved,
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    ControlMessage,
    ReservedForPrivate,
    Unknown,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Unknown
    }
}

impl From<u8> for Mode {
    fn from(data: u8) -> Self {
        match data {
            0 => Mode::Reserved,
            1 => Mode::SymmetricActive,
            2 => Mode::SymmetricPassive,
            3 => Mode::Client,
            4 => Mode::Server,
            5 => Mode::Broadcast,
            6 => Mode::ControlMessage,
            7 => Mode::ReservedForPrivate,
            _ => Self::default(),
        }
    }
}

#[derive(Default, Package)]
struct DefaultPackage {
    #[decoder(id = "app.genet.decoder.ntp", trigger_after("app.genet.decoder.udp"))]
    decoder: NtpDecoder,
}
