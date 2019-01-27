use genet_derive::{Attr, Package};
use genet_sdk::{decoder::*, prelude::*};

struct PcapLayerWorker {
    layer: LayerType<Link>,
    eth: DecoderStack,
}

impl Worker for PcapLayerWorker {
    fn decode(&mut self, stack: &mut LayerStack) -> Result<Status> {
        let data = stack.data();
        let mut layer = Layer::new(&self.layer, &data);
        let payload = data.get(self.layer.byte_size()..)?;
        layer.set_payload(&payload);

        stack.add_child(layer);
        self.eth.decode(stack)
    }
}

#[derive(Default, Clone)]
struct PcapLayerDecoder {}

impl Decoder for PcapLayerDecoder {
    fn new_worker(&self, ctx: &Context) -> Result<Box<Worker>> {
        Ok(Box::new(PcapLayerWorker {
            layer: LayerType::new("link"),
            eth: ctx.decoder("app.genet.decoder.eth")?,
        }))
    }
}

#[derive(Default, Package)]
struct DefaultPackage {
    #[decoder(id = "app.genet.decoder.pcap_layer")]
    decoder: PcapLayerDecoder,
}

#[derive(Attr)]
struct Link {
    r#type: u32,
    payload_length: u32,
    original_length: u32,

    #[attr(
        typ = "@datetime:unix",
        map = "(x >> 32) as f64 + (x & 0xffff_ffff) as f64 / 1_000_000f64"
    )]
    timestamp: Node<Cast<u64, f64>, Timestamp>,
}

#[derive(Attr)]
struct Timestamp {
    sec: u32,
    usec: u32,
}
