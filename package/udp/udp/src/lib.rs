use genet_derive::{Attr, Package};
use genet_sdk::{decoder::*, prelude::*};

struct UdpWorker {
    layer: LayerType<Udp>,
}

impl Worker for UdpWorker {
    fn decode(&mut self, stack: &mut LayerStack) -> Result<Status> {
        let data = stack.top().unwrap().payload();
        let mut layer = Layer::new(&self.layer, &data);
        let payload = data.get(self.layer.byte_size()..)?;
        layer.set_payload(&payload);
        stack.add_child(layer);
        Ok(Status::Done)
    }
}

#[derive(Default, Clone)]
struct UdpDecoder {}

impl Decoder for UdpDecoder {
    fn new_worker(&self, _ctx: &Context) -> Result<Box<Worker>> {
        Ok(Box::new(UdpWorker {
            layer: LayerType::new("udp"),
        }))
    }
}

#[derive(Default, Package)]
pub struct DefaultPackage {
    #[decoder(id = "app.genet.decoder.udp")]
    decoder: UdpDecoder,
}

#[derive(Attr)]
struct Udp {
    #[attr(alias = "_.src", typ = "@udp:port")]
    src: u16,

    #[attr(alias = "_.dst", typ = "@udp:port")]
    dst: u16,

    length: u16,

    checksum: u16,
}
