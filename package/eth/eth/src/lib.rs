use genet_derive::Attr;
use genet_sdk::{cast, decoder::*, prelude::*};

/// Ethernet
#[derive(Attr, Default)]
struct Eth {
    /// Source Hardware Address
    #[genet(alias = "_.src", typ = "@eth:mac", byte_size = 6)]
    src: cast::ByteSlice,

    /// Destination Hardware Address
    #[genet(alias = "_.dst", typ = "@eth:mac", byte_size = 6)]
    dst: cast::ByteSlice,

    #[genet(cond = "x <= 1500")]
    len: cast::UInt16BE,

    #[genet(cond = "x > 1500", typ = "@enum", align_before)]
    r#type: EnumNode<cast::UInt16BE, EthTypeEnum>,
}

#[derive(Attr)]
enum EthTypeEnum {
    IPv4,
    ARP,
    WOL,
    IPv6,
    EAP,
    Unknown,
}

impl Default for EthTypeEnum {
    fn default() -> Self {
        EthTypeEnum::Unknown
    }
}

impl From<u16> for EthTypeEnum {
    fn from(data: u16) -> EthTypeEnum {
        match data {
            0x0800 => EthTypeEnum::IPv4,
            0x0806 => EthTypeEnum::ARP,
            0x0842 => EthTypeEnum::WOL,
            0x86DD => EthTypeEnum::IPv6,
            0x888E => EthTypeEnum::EAP,
            _ => EthTypeEnum::Unknown,
        }
    }
}

struct EthWorker {
    layer: LayerType<Eth>,
    ipv4: WorkerBox,
}

impl Worker for EthWorker {
    fn decode(&mut self, stack: &mut LayerStack, data: &ByteSlice) -> Result<Status> {
        let layer = Layer::new(self.layer.as_ref().clone(), data);
        let typ = self.layer.r#type.try_get(&layer);
        stack.add_child(layer);

        let payload = data.try_get(self.layer.byte_size()..)?;
        match typ {
            Ok(EthTypeEnum::IPv4) => self.ipv4.decode(stack, &payload),
            _ => Ok(Status::Done),
        }
    }
}

#[derive(Clone)]
struct EthDecoder {}

impl Decoder for EthDecoder {
    fn new_worker(&self, ctx: &Context) -> Box<Worker> {
        Box::new(EthWorker {
            layer: LayerType::new("eth", Eth::default()),
            ipv4: ctx.decoder("ipv4").unwrap(),
        })
    }

    fn metadata(&self) -> Metadata {
        Metadata {
            id: "eth".into(),
            ..Metadata::default()
        }
    }
}

genet_decoders!(EthDecoder {});
