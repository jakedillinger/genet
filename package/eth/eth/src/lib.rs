use genet_derive::{Attr, Package};
use genet_sdk::{decoder::*, prelude::*};

/// Ethernet
#[derive(Attr)]
struct Eth {
    /// Source Hardware Address
    #[attr(alias = "_.src", typ = "@eth:mac", byte_size = 6)]
    src: Bytes,

    /// Destination Hardware Address
    #[attr(alias = "_.dst", typ = "@eth:mac", byte_size = 6)]
    dst: Bytes,

    #[attr(cond = "x <= 1500")]
    len: u16,

    #[attr(cond = "x > 1500", align_before)]
    r#type: Enum<u16, EthType>,
}

#[derive(Attr, Debug)]
enum EthType {
    IPv4,
    ARP,
    WOL,
    IPv6,
    EAP,
    Unknown,
}

impl Default for EthType {
    fn default() -> Self {
        EthType::Unknown
    }
}

impl From<u16> for EthType {
    fn from(data: u16) -> Self {
        match data {
            0x0800 => EthType::IPv4,
            0x0806 => EthType::ARP,
            0x0842 => EthType::WOL,
            0x86DD => EthType::IPv6,
            0x888E => EthType::EAP,
            _ => Self::default(),
        }
    }
}

struct EthWorker {
    layer: LayerType<Eth>,
    ipv4: DecoderStack,
    ipv6: DecoderStack,
    arp: DecoderStack,
}

impl Worker for EthWorker {
    fn decode(&mut self, stack: &mut LayerStack) -> Result<Status> {
        let data = stack.top().unwrap().payload();
        let mut layer = Layer::new(&self.layer, &data);

        let typ = self.layer.r#type.get(&layer);
        let payload = data.get(self.layer.byte_size()..)?;
        layer.set_payload(&payload);

        stack.add_child(layer);

        match typ {
            Ok(EthType::IPv4) => self.ipv4.decode(stack),
            Ok(EthType::IPv6) => self.ipv6.decode(stack),
            Ok(EthType::ARP) => self.arp.decode(stack),
            _ => Ok(Status::Done),
        }
    }
}

#[derive(Default, Clone)]
struct EthDecoder {}

impl Decoder for EthDecoder {
    fn new_worker(&self, ctx: &Context) -> Result<Box<Worker>> {
        Ok(Box::new(EthWorker {
            layer: LayerType::new("eth"),
            ipv4: ctx.decoder("app.genet.decoder.ipv4")?,
            ipv6: ctx.decoder("app.genet.decoder.ipv6")?,
            arp: ctx.decoder("app.genet.decoder.arp")?,
        }))
    }
}

#[derive(Default, Package)]
pub struct EthPackage {
    #[decoder(id = "app.genet.decoder.eth")]
    decoder: EthDecoder,
}
