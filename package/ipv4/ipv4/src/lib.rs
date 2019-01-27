use genet_derive::{Attr, Package};
use genet_sdk::{decoder::*, prelude::*};

struct IPv4Worker {
    layer: LayerType<IPv4>,
    tcp: DecoderStack,
    udp: DecoderStack,
}

impl Worker for IPv4Worker {
    fn decode(&mut self, stack: &mut LayerStack) -> Result<Status> {
        let data = stack.top().unwrap().payload();
        let mut layer = Layer::new(&self.layer, &data);

        let protocol = self.layer.protocol.get(&layer);
        let payload = data.get(self.layer.byte_size()..)?;
        layer.set_payload(&payload);
        stack.add_child(layer);

        match protocol {
            Ok(ProtoType::TCP) => self.tcp.decode(stack),
            Ok(ProtoType::UDP) => self.udp.decode(stack),
            _ => Ok(Status::Done),
        }
    }
}

#[derive(Default, Clone)]
struct IPv4Decoder {}

impl Decoder for IPv4Decoder {
    fn new_worker(&self, ctx: &Context) -> Result<Box<Worker>> {
        Ok(Box::new(IPv4Worker {
            layer: LayerType::new("ipv4"),
            tcp: ctx.decoder("app.genet.decoder.tcp")?,
            udp: ctx.decoder("app.genet.decoder.udp")?,
        }))
    }
}

#[derive(Default, Package)]
struct DefaultPackage {
    #[decoder(id = "app.genet.decoder.ipv4")]
    decoder: IPv4Decoder,
}

#[derive(Attr)]
struct IPv4 {
    #[attr(bit_size = 4, map = "x >> 4")]
    version: u8,

    #[attr(bit_size = 4, map = "x & 0b00001111")]
    header_length: u8,

    tos: u8,

    total_length: u16,

    id: u16,

    #[attr(bit_size = 3, map = "(x >> 5) & 0b0000_0111", typ = "@flags")]
    flags: Node<u8, Flags>,

    #[attr(bit_size = 13, map = "x & 0x1fff")]
    fragment_offset: u16,

    ttl: u8,

    protocol: Enum<u8, ProtoType>,

    checksum: u16,

    #[attr(alias = "_.src", typ = "@ipv4:addr", byte_size = 4)]
    src: Bytes,

    #[attr(alias = "_.dst", typ = "@ipv4:addr", byte_size = 4)]
    dst: Bytes,
}

#[derive(Attr)]
struct Flags {
    reserved: BitFlag,

    dont_fragment: BitFlag,

    more_fragments: BitFlag,
}

#[derive(Attr)]
enum ProtoType {
    ICPM,
    IGMP,
    TCP,
    UDP,
    Unknown,
}

impl Default for ProtoType {
    fn default() -> Self {
        ProtoType::Unknown
    }
}

impl From<u8> for ProtoType {
    fn from(data: u8) -> Self {
        match data {
            0x01 => ProtoType::ICPM,
            0x02 => ProtoType::IGMP,
            0x06 => ProtoType::TCP,
            0x11 => ProtoType::UDP,
            _ => Self::default(),
        }
    }
}
