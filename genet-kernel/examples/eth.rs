extern crate genet_sdk;

#[macro_use]
extern crate genet_derive;

/// Ethernet
#[derive(Attr, Default)]
struct Eth {
    /// Source Hardware Address
    #[genet(alias = "_.src", typ = "@eth:mac", byte_size = 6)]
    src: cast::ByteSlice,

    /// Destination Hardware Address
    #[genet(alias = "_.dst", typ = "@eth:mac", byte_size = 6)]
    dst: cast::ByteSlice,

    // Length or Protocol Type
    #[genet(padding)]
    _pad: cast::UInt16BE,

    /// Length
    len: Detach<cast::UInt16BE>,

    /// Protocol Type
    #[genet(typ = "@enum")]
    r#type: Node<cast::UInt16BE, EthType>,

    #[genet(bit_size = 1)]
    n1_ipv4_addr: cast::UInt8,

    #[genet(bit_size = 1)]
    n2: cast::UInt8,

    #[genet(bit_size = 6)]
    n3: cast::UInt8,

    n4: cast::UInt8,
}

type DUInt8 = Detach<cast::UInt8>;

#[derive(Attr, Default)]
struct EthType {
    ipv4: DUInt8,
    ipv6: DUInt8,
    arp: DUInt8,
}

use genet_sdk::{cast, decoder::*, field::*, prelude::*};

struct EthWorker {
    eth: LayerBox<Eth>,
}

impl Worker for EthWorker {
    fn decode(
        &mut self,
        _ctx: &mut Context,
        _stack: &LayerStack,
        parent: &mut Parent,
    ) -> Result<Status> {
        let data;

        if parent.id() == token!("[link-1]") {
            data = parent.payloads().next().unwrap().data();
        } else {
            return Ok(Status::Skip);
        }

        let mut layer = Layer::new(&ETH_CLASS, data);
        let len = LEN_ATTR.try_get(&layer)?.try_into()?;
        if len <= 1500 {
            layer.add_attr(&LEN_ATTR, 12..14);
        } else {
            layer.add_attr(&TYPE_ATTR, 12..14);
        }

        if let Some((typ, attr)) = get_type(len) {
            layer.add_attr(attr, 12..14);
            let payload = data.try_get(14..)?;
            layer.add_payload(Payload::new(payload, typ));
        }

        parent.add_child(layer);
        Ok(Status::Done)
    }
}

#[derive(Clone)]
struct EthDecoder {}

impl Decoder for EthDecoder {
    fn new_worker(&self, _ctx: &Context) -> Box<Worker> {
        let eth = LayerBox::new("eth", Eth::default());
        Box::new(EthWorker { eth })
    }

    fn metadata(&self) -> Metadata {
        Metadata {
            exec_type: ExecType::ParallelSync,
            ..Metadata::default()
        }
    }
}

def_layer_class!(ETH_CLASS, &ETH_ATTR,
    alias: "_.src" "eth.src",
    alias: "_.dst" "eth.dst"
);

def_attr_class!(ETH_ATTR, "eth", child: &SRC_ATTR, child: &DST_ATTR);

def_attr_class!(SRC_ATTR, "eth.src",
    typ: "@eth:mac",
    cast: cast::ByteSlice(),
    range: 0..6
);

def_attr_class!(DST_ATTR, "eth.dst",
    typ: "@eth:mac",
    cast: cast::ByteSlice(),
    range: 6..12
);

def_attr_class!(LEN_ATTR, "eth.len",
    cast: cast::UInt16BE(),
    range: 12..14
);

def_attr_class!(TYPE_ATTR, "eth.type",
    typ: "@enum",
    cast: cast::UInt16BE(),
    range: 12..14
);

fn get_type(val: u64) -> Option<(Token, &'static AttrClass)> {
    match val {
        0x0800 => Some((
            token!("@data:ipv4"),
            attr_class_lazy!("eth.type.ipv4", typ: "@novalue", value: true),
        )),
        0x0806 => Some((
            token!("@data:arp"),
            attr_class_lazy!("eth.type.arp", typ: "@novalue", value: true),
        )),
        0x0842 => Some((
            token!("@data:wol"),
            attr_class_lazy!("eth.type.wol", typ: "@novalue", value: true),
        )),
        0x86DD => Some((
            token!("@data:ipv6"),
            attr_class_lazy!("eth.type.ipv6", typ: "@novalue", value: true),
        )),
        0x888E => Some((
            token!("@data:eap"),
            attr_class_lazy!("eth.type.eap", typ: "@novalue", value: true),
        )),
        _ => None,
    }
}

genet_decoders!(EthDecoder {});
