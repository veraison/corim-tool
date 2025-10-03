// SPDX-License-Identifier: Apache-2.0

use corim_rs::corim::Corim;
use log::{debug, info};

use std::fs::File;
use std::io::Write;
use std::str::from_utf8;

use crate::result::{Error, Result};
use crate::util::open_output;

pub(crate) fn parse(
    source: &str,
    dest: Option<String>,
    meta_path: Option<String>,
    pretty: bool,
    force: bool,
) -> Result<()> {
    debug!(pretty:?; "");
    debug!("reading CoRIM from {}...", source);
    let in_file = File::open(source)?;
    let corim = Corim::from_cbor(&in_file)?;

    debug!(corim:?; "");
    if let Some(signed) = corim.as_signed_ref() {
        match from_utf8(signed.kid.as_slice()) {
            Ok(kid_str) => {
                info!("kid: {}", kid_str);
            }
            Err(_) => {
                info!("kid: {:x?}", signed.kid.as_slice());
            }
        }
    }

    if let Some(meta_path) = meta_path {
        if let Some(signed) = corim.as_signed_ref() {
            debug!("writing meta to {}...", meta_path);

            let mut meta_file = match force {
                true => File::create(meta_path)?,
                false => File::create_new(meta_path)?,
            };

            let meta_json = match pretty {
                true => signed.meta.to_json_pretty()?,
                false => signed.meta.to_json()?,
            };

            write!(meta_file, "{}", meta_json)?;
        } else {
            return Err(Error::custom("meta path specified for unsigned CoRIM"));
        }
    }

    let mut out = open_output(dest, force)?;

    let json = match pretty {
        true => corim.into_map().to_json_pretty()?,
        false => corim.into_map().to_json()?,
    };

    write!(out, "{}", json)?;

    Ok(())
}
