// SPDX-License-Identifier: Apache-2.0

use asn1_rs::oid;
use corim_rs::openssl::OpensslSigner;
use corim_rs::{Bytes, CoseEllipticCurve, CoseKey, CoseKty};
use corim_rs::{TaggedSignedCorim, corim::Corim};
use log::{debug, info};
use rustls_native_certs::load_native_certs;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use std::fs::File;
use std::io::Read;

use crate::result::{Error, Result};
use crate::util::read_der_from_path;

fn load_root_buffers(paths: &Vec<String>) -> Result<Vec<Vec<u8>>> {
    let result = load_native_certs();
    if let Some(err) = result.errors.first() {
        return Err(Error::custom(format!("loading system certs: {}", err)));
    }

    let mut roots = Vec::new();
    for cert in result.certs {
        roots.push(cert.as_ref().to_vec());
    }

    for path in paths {
        roots.push(read_der_from_path(path)?)
    }

    Ok(roots)
}

fn parse_certs<'a, I: Iterator<Item = &'a [u8]>>(bufs: I) -> Result<Vec<X509Certificate<'a>>> {
    bufs.map(|der| {
        X509Certificate::from_der(der)
            .map_err(|e| Error::custom(format!("parsing root certs: {}", e)))
            .map(|(_, cert)| cert)
    })
    .collect::<Result<Vec<_>>>()
}

const PRIME256V1: asn1_rs::Oid<'static> = oid!(1.2.840.10045.3.1.7);
const SECP384: asn1_rs::Oid<'static> = oid!(1.3.132.0.34);
const SECP521: asn1_rs::Oid<'static> = oid!(1.3.132.0.35);

fn create_verifier_from_x5chain(
    signed: &TaggedSignedCorim,
    root_bufs: Vec<Vec<u8>>,
) -> Result<OpensslSigner> {
    if let Some(ref x5chain) = signed.x5chain {
        let roots: Vec<X509Certificate> = parse_certs(root_bufs.iter().map(|v| v.as_ref()))?;
        let certs: Vec<X509Certificate> = parse_certs(x5chain.iter().map(|b| b.as_slice()))?;

        crate::util::verify_chain(certs.as_slice())?;

        let chain_root = certs.last().unwrap();
        if !roots.iter().any(|root| {
            chain_root
                .verify_signature(Some(root.tbs_certificate.public_key()))
                .is_ok()
        }) {
            return Err(Error::custom("x5chain verification failed"));
        }

        let pkinfo = certs.first().unwrap().public_key();
        let cose_key = match pkinfo.parsed().map_err(Error::custom)? {
            PublicKey::EC(ec_point) => {
                let raw = ec_point.data();
                if raw[0] != 0x04 {
                    return Err(Error::custom("invalid EC format"));
                }

                let coord_size = (raw.len() - 1) / 2;
                let x: Bytes = ec_point.data()[1..1 + coord_size].into();
                let y: Bytes = ec_point.data()[1 + coord_size..].into();

                let oid_crv = pkinfo
                    .algorithm
                    .parameters()
                    .as_ref()
                    .ok_or(Error::custom("could not extract curve vrom key info"))?
                    .as_oid()
                    .map_err(Error::custom)?;

                let crv = if oid_crv == PRIME256V1 {
                    Ok(CoseEllipticCurve::P256)
                } else if oid_crv == SECP384 {
                    Ok(CoseEllipticCurve::P384)
                } else if oid_crv == SECP521 {
                    Ok(CoseEllipticCurve::P521)
                } else {
                    Err(Error::custom(format!(
                        "x5chain: unsupported algroithim: {:?}",
                        oid_crv
                    )))
                }?;

                CoseKey {
                    kty: CoseKty::Ec2,
                    kid: None,
                    alg: None,
                    key_ops: None,
                    base_iv: None,
                    crv: Some(crv),
                    x: Some(x),
                    y: Some(y),
                    d: None,
                    k: None,
                }
            }
            _ => return Err(Error::custom("unsupported key type in x5chain")),
        };

        Ok(cose_key.into())
    } else {
        Err(Error::custom("x5chain header not set in CoRIM"))
    }
}

pub(crate) fn verify(source: &str, key: &Option<String>, root_paths: &Vec<String>) -> Result<()> {
    debug!("reading CoRIM from {}...", source);
    let in_file = File::open(source)?;
    let corim = Corim::from_cbor(&in_file)?;
    let mut verifier: Option<OpensslSigner> = None;

    if let Some(key_path) = key {
        debug!("reading signing key form {}...", key_path);
        let mut key_file = File::open(key_path)?;

        let mut key_buf = Vec::<u8>::new();
        key_file.read_to_end(&mut key_buf)?;

        debug!("creating verifier...");
        verifier = Some(OpensslSigner::public_key_from_pem(&key_buf)?);
    }

    if let Corim::Signed(signed) = corim {
        if verifier.is_none() {
            let root_bufs = load_root_buffers(root_paths)?;
            verifier = Some(create_verifier_from_x5chain(&signed, root_bufs)?);
        }

        debug!("verifying signature...");
        match signed.verify_signature(verifier.unwrap()) {
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
