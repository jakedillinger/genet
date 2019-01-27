use byteorder::{LittleEndian, WriteBytesExt};
use genet_derive::Package;
use genet_sdk::{prelude::*, url::Url, writer::*};

use std::{
    fs::File,
    io::{BufWriter, Write},
};

#[derive(Default, Clone)]
struct PcapFileWriter {}

impl Writer for PcapFileWriter {
    fn new_worker(&self, _ctx: &Context, url: &Url) -> Result<Box<Worker>> {
        let file = File::create(&url.to_file_path().unwrap())?;
        let mut writer = BufWriter::new(file);
        writer.write_all(&[0x4d, 0x3c, 0xb2, 0xa1])?;
        Ok(Box::new(PcapFileWorker {
            writer,
            header: false,
        }))
    }
}

#[derive(Default, Package)]
pub struct DefaultPackage {
    #[writer(
        id = "app.genet.writer.pcap-file",
        filter(name = "Pcap File", ext = "pcap")
    )]
    writer: PcapFileWriter,
}

struct PcapFileWorker {
    writer: BufWriter<File>,
    header: bool,
}

impl PcapFileWorker {
    fn write_header(&mut self, snaplen: u32, network: u32) -> Result<()> {
        if !self.header {
            self.header = true;
            let var_major = 2u16;
            let var_minor = 4u16;
            let thiszone = 0i32;
            let sigfigs = 0u32;
            self.writer.write_u16::<LittleEndian>(var_major)?;
            self.writer.write_u16::<LittleEndian>(var_minor)?;
            self.writer.write_i32::<LittleEndian>(thiszone)?;
            self.writer.write_u32::<LittleEndian>(sigfigs)?;
            self.writer.write_u32::<LittleEndian>(snaplen)?;
            self.writer.write_u32::<LittleEndian>(network)?;
        }
        Ok(())
    }
}

impl Worker for PcapFileWorker {
    fn write(&mut self, _index: u32, layer: &Layer) -> Result<()> {
        let data = layer.payload();
        let incl_len = data.len();
        let mut orig_len = 0;
        let mut ts_sec = 0;
        let mut ts_usec = 0;
        let mut link = 0;

        if let Some(attr) = layer.attr(token!("link.originalLength")) {
            orig_len = attr.get()?.try_into()?;
        }
        if let Some(attr) = layer.attr(token!("link.type")) {
            link = attr.get()?.try_into()?;
        }
        if let Some(attr) = layer.attr(token!("link.timestamp.sec")) {
            ts_sec = attr.get()?.try_into()?;
        }
        if let Some(attr) = layer.attr(token!("link.timestamp.usec")) {
            ts_usec = attr.get()?.try_into()?;
        }

        self.write_header(0, link as u32)?;

        self.writer.write_u32::<LittleEndian>(ts_sec as u32)?;
        self.writer.write_u32::<LittleEndian>(ts_usec as u32)?;
        self.writer.write_u32::<LittleEndian>(incl_len as u32)?;
        self.writer.write_u32::<LittleEndian>(orig_len as u32)?;
        self.writer.write_all(&data)?;
        Ok(())
    }
}
