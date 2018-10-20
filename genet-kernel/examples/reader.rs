#[macro_use]
extern crate genet_sdk;

use genet_sdk::{context::Context, layer::Layer, reader::*, result::Result, slice::ByteSlice};
use std::iter;

pub fn tcp_ipv4_pcap() -> &'static [u8] {
    &[
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x33, 0xf6, 0x7e, 0x58, 0x88, 0x65,
        0x0d, 0x00, 0x42, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0xac, 0xbc, 0x32, 0xbc, 0x2a,
        0x87, 0x80, 0x13, 0x82, 0x62, 0xa2, 0x45, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x69, 0xaf,
        0x40, 0x00, 0x31, 0x06, 0x01, 0xf7, 0xca, 0xe8, 0xee, 0x28, 0xc0, 0xa8, 0x64, 0x64, 0x00,
        0x50, 0xc4, 0x27, 0x22, 0xdd, 0xb1, 0xc0, 0x63, 0x6a, 0x47, 0x9b, 0x80, 0x10, 0x00, 0x72,
        0xf7, 0x6c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xf9, 0x28, 0x89, 0x4f, 0x61, 0x8f, 0x78,
        0x9d,
    ]
}

#[derive(Clone)]
struct TestReader {}

impl Reader for TestReader {
    fn new_worker(&self, _ctx: &Context, _arg: &str) -> Result<Box<Worker>> {
        Ok(Box::new(TestWorker {}))
    }

    fn metadata(&self) -> Metadata {
        Metadata {
            id: "app.genet.reader.test-input".into(),
            ..Metadata::default()
        }
    }
}

struct TestWorker {}

impl Worker for TestWorker {
    fn read(&mut self) -> Result<Vec<Layer>> {
        let layers = iter::repeat(())
            .take(1000)
            .map(|_| Layer::new(&ETH_CLASS, ByteSlice::from(tcp_ipv4_pcap())))
            .collect();
        Ok(layers)
    }
}

def_layer_class!(ETH_CLASS, "[link-1]");

genet_readers!(TestReader {});
