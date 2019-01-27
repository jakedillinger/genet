use byteorder::{BigEndian, WriteBytesExt};
use genet_derive::Package;
use genet_sdk::{prelude::*, reader::*, url::Url};
use pcap::Header;
use std::{
    collections::{hash_map::RandomState, HashMap},
    iter::FromIterator,
};

use std::{
    io::{BufRead, BufReader, Cursor, Error, ErrorKind, Read},
    process::{Child, ChildStdout, Command, Stdio},
};

#[derive(Default, Clone)]
struct PcapReader {}

impl Reader for PcapReader {
    fn new_worker(&self, _ctx: &Context, url: &Url) -> Result<Box<Worker>> {
        let query: HashMap<_, _, RandomState> = HashMap::from_iter(url.query_pairs());
        let cmd = query["cmd"].to_string();
        let args = query["args"].split(' ').collect::<Vec<_>>();
        let link: u32 = query["link"].parse()?;
        let mut child = Command::new(&cmd)
            .args(&args)
            .stdout(Stdio::piped())
            .spawn()?;
        let reader = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| Error::new(ErrorKind::Other, "no stdout"))?,
        );
        Ok(Box::new(PcapWorker {
            child,
            reader,
            link,
        }))
    }
}

#[derive(Default, Package)]
pub struct DefaultPackage {
    #[reader(id = "app.genet.reader.pcap")]
    reader: PcapReader,
}

struct PcapWorker {
    child: Child,
    reader: BufReader<ChildStdout>,
    link: u32,
}

impl Worker for PcapWorker {
    fn read(&mut self) -> Result<Vec<Bytes>> {
        let mut header = String::new();
        self.reader.read_line(&mut header)?;
        let header = header.trim();
        if header.is_empty() {
            return Ok(vec![]);
        }
        let header: Header = serde_json::from_str(header)?;
        let size = header.datalen as usize;

        let metalen = 20;
        let mut data = vec![0u8; size + metalen];
        self.reader.read_exact(&mut data[metalen..])?;

        let mut cur = Cursor::new(data);
        cur.write_u32::<BigEndian>(self.link)?;
        cur.write_u32::<BigEndian>(header.datalen)?;
        cur.write_u32::<BigEndian>(header.actlen)?;
        cur.write_u32::<BigEndian>(header.ts_sec)?;
        cur.write_u32::<BigEndian>(header.ts_usec)?;

        let payload = Bytes::from(cur.into_inner());
        Ok(vec![payload])
    }

    fn layer_id(&self) -> Token {
        token!("[pcap]")
    }
}

impl Drop for PcapWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
