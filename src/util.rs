// SPDX-License-Identifier: Apache-2.0
//
use x509_parser::prelude::*;

use std::fs::{self, File};
use std::io::{self, Cursor, Write};
use std::path::Path;

use crate::result::{Error, Result};

pub(crate) fn open_output(path: Option<String>, force: bool) -> Result<Box<dyn Write>> {
    if path.is_none() {
        return Ok(Box::new(io::stdout().lock()));
    }

    if force {
        Ok(Box::new(
            File::create(path.unwrap()).map_err(Error::custom)?,
        ))
    } else {
        Ok(Box::new(
            File::create_new(path.unwrap()).map_err(Error::custom)?,
        ))
    }
}

pub(crate) fn read_der_from_path<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let mut buf = fs::read(path.as_ref()).map_err(Error::custom)?;

    match path.as_ref().extension().and_then(|ext| ext.to_str()) {
        Some("pem") => {
            let (pem, _) = Pem::read(Cursor::new(buf)).map_err(Error::custom)?;
            buf = pem.contents;
        }
        _ => (),
    }

    Ok(buf)
}

pub(crate) fn verify_chain(certs: &[X509Certificate<'_>]) -> Result<()> {
    match certs.len() {
        0 => Err(Error::custom("empty chain")),
        1 => Ok(()),
        _ => {
            for pair in certs.windows(2) {
                pair[0]
                    .verify_signature(Some(pair[1].tbs_certificate.public_key()))
                    .map_err(|e| Error::custom(format!("x5chain: {}", e)))?;
            }

            Ok(())
        }
    }
}
