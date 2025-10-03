// SPDX-License-Identifier: Apache-2.0

use corim_rs::corim::Corim;
use corim_rs::openssl::OpensslSigner;

use log::{debug, info};

use std::fs::File;
use std::io::Read;

use crate::result::{Error, Result};

pub(crate) fn verify(source: &str, key: &str) -> Result<()> {
    debug!("reading CoRIM from {}...", source);
    let in_file = File::open(source)?;
    let corim = Corim::from_cbor(&in_file)?;

    debug!("reading signing key form {}...", key);
    let mut key_file = File::open(key)?;
    let mut key_buf = Vec::<u8>::new();

    key_file.read_to_end(&mut key_buf)?;

    debug!("creating verifier...");
    let verifier = OpensslSigner::public_key_from_pem(&key_buf)?;

    if let Corim::Signed(signed) = corim {
        debug!("verifying signature...");
        match signed.verify_signature(verifier) {
            Ok(_) => {
                info!("signature OK");
                Ok(())
            }
            Err(err) => Err(Error::custom(format!(
                "signature verification failed: {}",
                err
            ))),
        }
    } else {
        Err(Error::custom("CoRIM must be signed"))
    }
}
