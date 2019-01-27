use genet_derive::{Attr, Package};
use genet_sdk::{decoder::*, prelude::*};

struct TcpWorker {
    layer: LayerType<Tcp>,
}

impl Worker for TcpWorker {
    fn decode(&mut self, stack: &mut LayerStack) -> Result<Status> {
        let data = stack.top().unwrap().payload();
        let mut layer = Layer::new(&self.layer, &data);

        let data_offset = self.layer.data_offset.get(&layer)? as usize;
        let data_offset = data_offset * 4;

        let opt_offset = self.layer.byte_size();
        let mut offset = opt_offset;
        while offset < data_offset {
            let typ = layer.data().get(offset)?;
            if typ <= 1 {
                if typ == 1 {
                    layer.add_attr(&self.layer.options.nop, offset..offset + 1);
                }
                offset += 1;
                continue;
            }
            let len = layer.data().get(offset + 1)? as usize;
            match typ {
                2 => {
                    layer.add_attr(&self.layer.options.mss, offset + 2..offset + len);
                }
                3 => {
                    layer.add_attr(&self.layer.options.scale, offset + 2..offset + len);
                }
                4 => {
                    layer.add_attr(
                        &self.layer.options.selective_ack_permitted,
                        offset..offset + len,
                    );
                }
                5 => {
                    layer.add_attr(&self.layer.options.selective_ack, offset + 2..offset + len);
                }
                8 => {
                    layer.add_attr(&self.layer.options.ts, offset + 2..offset + len);
                }
                _ => {}
            }
            offset += len;
        }
        layer.add_attr(&self.layer.options, opt_offset..offset);

        stack.add_child(layer);
        Ok(Status::Done)
    }
}

#[derive(Default, Clone)]
struct TcpDecoder {}

impl Decoder for TcpDecoder {
    fn new_worker(&self, _ctx: &Context) -> Result<Box<Worker>> {
        Ok(Box::new(TcpWorker {
            layer: LayerType::new("tcp"),
        }))
    }
}

#[derive(Default, Package)]
struct DefaultPackage {
    #[decoder(id = "app.genet.decoder.tcp")]
    decoder: TcpDecoder,
}

#[derive(Attr)]
struct Tcp {
    #[attr(alias = "_.src", typ = "@tcp:port")]
    src: u16,

    #[attr(alias = "_.dst", typ = "@tcp:port")]
    dst: u16,

    seq: u32,

    ack: u32,

    #[attr(bit_size = 4, map = "x >> 4")]
    data_offset: Node<u8>,

    #[attr(bit_size = 12, typ = "@flags", map = "x & 0xfff")]
    flags: Node<u16, Flags>,

    window: u16,

    checksum: u16,

    urgent: u16,

    #[attr(detach, byte_size = 1)]
    options: Node<Bytes, Options>,
}

#[derive(Attr)]
struct Flags {
    #[attr(bit_size = 3, skip)]
    reserved: u8,

    ns: BitFlag,

    cwr: BitFlag,

    ece: BitFlag,

    urg: BitFlag,

    ack: BitFlag,

    psh: BitFlag,

    rst: BitFlag,

    syn: BitFlag,

    fin: BitFlag,
}

#[derive(Attr)]
struct Options {
    #[attr(detach)]
    nop: Node<u8>,

    #[attr(detach)]
    mss: Node<u16>,

    #[attr(detach)]
    scale: Node<u8>,

    #[attr(detach)]
    selective_ack_permitted: Node<u8>,

    #[attr(detach, byte_size = 1)]
    selective_ack: Node<Bytes>,

    #[attr(detach, typ = "@nested")]
    ts: Node<Timestamp>,
}

#[derive(Attr)]
struct Timestamp {
    my: u32,
    echo: u32,
}
