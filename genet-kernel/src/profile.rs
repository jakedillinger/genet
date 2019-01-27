use bincode;
use failure::{err_msg, Error};
use fnv::FnvHashMap;
use genet_abi::{
    alloc::Allocator, context::Context, decoder::DecoderData, genet_abi_version,
    reader::ReaderData, token::TokenRegistry, writer::WriterData,
};
use genet_sdk::package::{Component, Package};
use libloading::Library;
use num_cpus;
use serde_derive::Serialize;
use std::{mem, slice};

impl Default for Profile {
    fn default() -> Self {
        Self {
            concurrency: 4,
            packages: Vec::new(),
            config: FnvHashMap::default(),
        }
    }
}

#[derive(Serialize, Clone)]
pub struct Profile {
    concurrency: u32,
    packages: Vec<Package>,
    config: FnvHashMap<String, String>,
}

impl Profile {
    pub fn set_concurrency(&mut self, concurrency: u32) {
        self.concurrency = if concurrency > 0 {
            concurrency
        } else {
            num_cpus::get() as u32
        };
    }

    pub fn concurrency(&self) -> u32 {
        self.concurrency
    }

    pub fn get_config(&self, key: &str) -> Option<String> {
        self.config.get(key).map(|s| s.to_string())
    }

    pub fn set_config(&mut self, key: &str, value: &str) {
        self.config
            .entry(String::from(key))
            .or_insert_with(|| String::from(value));
    }

    pub fn decoders(&self) -> impl Iterator<Item = &DecoderData> {
        self.packages
            .iter()
            .map(|pkg| {
                pkg.components.iter().filter_map(|comp| {
                    if let Component::Decoder(comp) = comp {
                        Some(comp)
                    } else {
                        None
                    }
                })
            })
            .flatten()
    }

    pub fn readers(&self) -> impl Iterator<Item = &ReaderData> {
        self.packages
            .iter()
            .map(|pkg| {
                pkg.components.iter().filter_map(|comp| {
                    if let Component::Reader(comp) = comp {
                        Some(comp)
                    } else {
                        None
                    }
                })
            })
            .flatten()
    }

    pub fn writers(&self) -> impl Iterator<Item = &WriterData> {
        self.packages
            .iter()
            .map(|pkg| {
                pkg.components.iter().filter_map(|comp| {
                    if let Component::Writer(comp) = comp {
                        Some(comp)
                    } else {
                        None
                    }
                })
            })
            .flatten()
    }

    pub fn context(&self) -> Context {
        let mut ctx = Context::default();
        ctx.set_decoders(self.decoders().cloned().collect());
        ctx
    }

    pub fn register_component(&mut self, comp: Component) {
        self.components.push(comp);
    }

    pub fn load_library(&mut self, path: &str) -> Result<(), Error> {
        let lib = Library::new(path)?;

        type FnVersion = extern "C" fn() -> u64;
        type FnRegisterTokenRegistry = extern "C" fn(TokenRegistry);
        type FnRegisterAllocator = extern "C" fn(Allocator);

        type FnLoadPackageCallback = extern "C" fn(*const u8, u64, *mut Vec<u8>);
        type FnLoadPackage = extern "C" fn(*mut Vec<u8>, FnLoadPackageCallback);

        {
            let func = unsafe { lib.get::<FnVersion>(b"genet_abi_version")? };

            // In the initial development, minor version changes may break ABI.
            fn canonical(ver: u64) -> u64 {
                if ver >> 32 == 0 {
                    ver
                } else {
                    ver & (0xffff_ffff << 32)
                }
            }

            if canonical(genet_abi_version()) != canonical(func()) {
                return Err(err_msg("abi version mismatch"));
            }

            let func =
                unsafe { lib.get::<FnRegisterAllocator>(b"genet_abi_v1_register_allocator")? };
            func(Allocator::default());

            let func = unsafe {
                lib.get::<FnRegisterTokenRegistry>(b"genet_abi_v1_register_token_registry")?
            };
            func(TokenRegistry::default());
        }

        if let Ok(func) = unsafe { lib.get::<FnLoadPackage>(b"genet_abi_v1_load_package") } {
            extern "C" fn cb(data: *const u8, len: u64, dst: *mut Vec<u8>) {
                unsafe { *dst = slice::from_raw_parts(data, len as usize).to_vec() };
            }
            let mut buf = Vec::new();
            func(&mut buf, cb);
            if let Ok(pkg) = bincode::deserialize::<Package>(&buf) {
                self.packages.push(pkg);
            }
        }

        mem::forget(lib);
        Ok(())
    }
}
