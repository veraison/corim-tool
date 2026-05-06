// SPDX-License-Identifier: Apache-2.0

use corim_rs::core::{Bytes, CoseAlgorithm, CoseEllipticCurve};
use corim_rs::corim::{Corim, CorimMap, CorimMetaMapBuilder, CoseKeyOwner, SignedCorimBuilder};
use corim_rs::openssl::OpensslSigner;
use corim_rs::{CorimMetaMap, OneOrMore};
use log::debug;
use x509_parser::prelude::*;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::result::{Error, Result};
use crate::util::open_output;

fn alg_from_signer(signer: &OpensslSigner) -> Result<CoseAlgorithm> {
    let key = signer.to_cose_key();
    match key.crv {
        Some(CoseEllipticCurve::P256) => Ok(CoseAlgorithm::ES256),
        Some(CoseEllipticCurve::P384) => Ok(CoseAlgorithm::ES384),
        Some(CoseEllipticCurve::P521) => Ok(CoseAlgorithm::ES512),
        Some(other) => Err(Error::custom(format!("unsupported curve {}", other))),
        None => Err(Error::missing_field("CoseKey", "crv")),
    }
}

fn parse_cert(der: &'_ [u8]) -> Result<X509Certificate<'_>> {
    let (rest, cert) = parse_x509_certificate(der).map_err(Error::custom)?;
    if rest.len() > 0 {
        return Err(Error::custom("trailing bytes"));
    }

    Ok(cert)
}

fn bufs_to_x5chain(certs: Vec<Vec<u8>>) -> Option<OneOrMore<Bytes>> {
    let mut it = certs.into_iter();
    match it.next() {
        None => None,
        Some(first) => {
            let rest: Vec<Vec<u8>> = it.collect();
            if rest.is_empty() {
                Some(OneOrMore::One(first.into()))
            } else {
                let mut all: Vec<Bytes> = vec![first.into()];
                all.extend(rest.into_iter().map(|v| v.into()).collect::<Vec<Bytes>>());
                Some(OneOrMore::More(all))
            }
        }
    }
}

pub(crate) fn compile(
    source: &str,
    key: &Option<String>,
    kid: &Option<String>,
    cert_paths: &Vec<String>,
    dest: Option<String>,
    meta_path: Option<String>,
    force: bool,
) -> Result<()> {
    debug!("reading JSON from {}...", source);
    let in_file = File::open(source)?;
    let corim_map = CorimMap::from_json(in_file)?;

    debug!(corim_map:?; "");

    let mut out = open_output(dest, force)?;
    let buf;

    if let Some(key_path) = key {
        let mut x5chain: Option<OneOrMore<Bytes>> = None;
        if !cert_paths.is_empty() {
            debug!("assembling X5Chain...");
            let bufs = cert_paths
                .iter()
                .map(|p| crate::util::read_der_from_path(p))
                .collect::<Result<Vec<Vec<u8>>>>()?;
            let certs = bufs
                .iter()
                .map(|b| parse_cert(b))
                .collect::<Result<Vec<X509Certificate>>>()?;
            crate::util::verify_chain(certs.as_slice())?;
            x5chain = bufs_to_x5chain(bufs);
        }

        debug!("reading signing key from {}...", key_path);
        let mut key_file = File::open(key_path)?;
        let mut key_buf = Vec::<u8>::new();

        key_file.read_to_end(&mut key_buf)?;

        debug!("creating signer & establishing algorithm...");
        let signer = OpensslSigner::private_key_from_pem(&key_buf)?;
        let alg = alg_from_signer(&signer)?;
        debug!(alg:?; "");

        let meta;
        if let Some(meta_path) = meta_path {
            debug!("reading meta...");
            let meta_file = File::open(meta_path)?;
            meta = CorimMetaMap::from_json(meta_file)?;
        } else {
            debug!("creating meta...");
            meta = CorimMetaMapBuilder::new()
                .signer_name("corim-tool".into())
                .build()?;
        }

        let kid = match kid {
            Some(kid) => kid.as_bytes(),
            None => Path::new(key_path)
                .file_name()
                .unwrap() // will always succeed as we've already read from the path above (so
                // must be a file).
                .to_str()
                .unwrap() // will always succeed as key_path is a string.
                .as_bytes(),
        };

        debug!("signing CoRIM...");
        let corim: Corim = match x5chain {
            None => SignedCorimBuilder::new(),
            Some(x5c) => SignedCorimBuilder::new().x5chain(x5c),
        }
        .corim_map(corim_map)
        .alg(alg)
        .meta(meta)
        .kid(kid.into())
        .build_and_sign(signer)?
        .into();

        buf = corim.to_cbor()?;
    } else {
        if meta_path.is_some() {
            return Err(Error::custom(
                "meta can only be specified when signing (--key must also be specified",
            ));
        }

        buf = Corim::from(corim_map).to_cbor()?;
    }

    out.write_all(&buf)?;

    Ok(())
}
