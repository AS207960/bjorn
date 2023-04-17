use super::types;
use foreign_types::{ForeignTypeRef, ForeignType};

pub struct OCSPIssuer {
    pub(crate) issuer: openssl::x509::X509,
    pub(crate) signer: openssl::pkcs12::ParsedPkcs12_2,
    pub(crate) grpc_client: super::processing::OCSPClient,
    pub(crate) cert_id: String,
    pub(crate) pub_key_sha1: Vec<u8>,
}

impl OCSPIssuer {
    pub fn new(issuer: openssl::x509::X509, signer: openssl::pkcs12::ParsedPkcs12_2, grpc_client: super::processing::OCSPClient, cert_id: String) -> OCSPIssuer {
        let issuer_key = unsafe {
            let issuer_key_string = super::proto::X509_get0_pubkey_bitstr( signer.cert.as_ref().expect("No signer cert").as_ptr());
            std::slice::from_raw_parts(
                openssl_sys::ASN1_STRING_get0_data(issuer_key_string.cast()),
                openssl_sys::ASN1_STRING_length(issuer_key_string.cast()) as usize,
            )
        };
        let issuer_key_sha1 = openssl::hash::hash(
            openssl::hash::MessageDigest::sha1(), &issuer_key,
        ).unwrap().to_vec();

        OCSPIssuer {
            issuer,
            signer,
            grpc_client,
            cert_id,
            pub_key_sha1: issuer_key_sha1
        }
    }
}

pub(crate) struct Pkcs12Debug<'a>(pub(crate) &'a openssl::pkcs12::ParsedPkcs12_2);

impl std::fmt::Debug for Pkcs12Debug<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ParsedPkcs12")
            .field("pkey", &self.0.pkey)
            .field("cert", &self.0.cert)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OCSPIssuer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OCSPIssuer")
            .field("issuer", &self.issuer)
            .field("signer", &Pkcs12Debug(&self.signer))
            .field("grpc_client", &self.grpc_client)
            .field("cert_id", &self.cert_id)
            .finish()
    }
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct OCSPIssuerKey<'a> {
    name_hash: std::borrow::Cow<'a, [u8]>,
    key_hash: std::borrow::Cow<'a, [u8]>,
}

type OCSPIssuerMap<'a> = std::collections::HashMap<OCSPIssuerKey<'a>, usize>;

#[derive(Debug)]
pub struct InnerOCSPIssuers<'a> {
    by_sha1: OCSPIssuerMap<'a>,
    by_sha224: OCSPIssuerMap<'a>,
    by_sha256: OCSPIssuerMap<'a>,
    by_sha384: OCSPIssuerMap<'a>,
    by_sha512: OCSPIssuerMap<'a>,
    by_sha3_224: OCSPIssuerMap<'a>,
    by_sha3_256: OCSPIssuerMap<'a>,
    by_sha3_384: OCSPIssuerMap<'a>,
    by_sha3_512: OCSPIssuerMap<'a>,
}

#[derive(Debug)]
pub struct OCSPIssuers<'a> {
    issuers: Vec<OCSPIssuer>,
    inner_issuers: InnerOCSPIssuers<'a>,
}

impl OCSPIssuers<'_> {
    pub fn new(issuers: Vec<OCSPIssuer>) -> OCSPIssuers<'static> {
        let inner_issuers = Self::issuer_list(&issuers);
        OCSPIssuers {
            inner_issuers,
            issuers,
        }
    }

    pub fn find_issuer(&self, cert_id: &types::CertID) -> Option<&OCSPIssuer> {
        let lookup_map = match &cert_id.hash_algorithm {
            types::HashAlgorithm::SHA1 => &self.inner_issuers.by_sha1,
            types::HashAlgorithm::SHA224 => &self.inner_issuers.by_sha224,
            types::HashAlgorithm::SHA256 => &self.inner_issuers.by_sha256,
            types::HashAlgorithm::SHA384 => &self.inner_issuers.by_sha384,
            types::HashAlgorithm::SHA512 => &self.inner_issuers.by_sha512,
            types::HashAlgorithm::SHA3_224 => &self.inner_issuers.by_sha3_224,
            types::HashAlgorithm::SHA3_256 => &self.inner_issuers.by_sha3_256,
            types::HashAlgorithm::SHA3_384 => &self.inner_issuers.by_sha3_384,
            types::HashAlgorithm::SHA3_512 => &self.inner_issuers.by_sha3_512,
            _ => return None
        };

        let lookup_key = OCSPIssuerKey {
            name_hash: std::borrow::Cow::Borrowed(cert_id.issuer_name_hash),
            key_hash: std::borrow::Cow::Borrowed(cert_id.issuer_key_hash),
        };

        let issuer_index = lookup_map.get(&lookup_key)?;
        Some(&self.issuers[*issuer_index])
    }

    fn issuer_list(issuers: &[OCSPIssuer]) -> InnerOCSPIssuers<'static> {
        let mut by_sha1 = OCSPIssuerMap::new();
        let mut by_sha224 = OCSPIssuerMap::new();
        let mut by_sha256 = OCSPIssuerMap::new();
        let mut by_sha384 = OCSPIssuerMap::new();
        let mut by_sha512 = OCSPIssuerMap::new();
        let mut by_sha3_224 = OCSPIssuerMap::new();
        let mut by_sha3_256 = OCSPIssuerMap::new();
        let mut by_sha3_384 = OCSPIssuerMap::new();
        let mut by_sha3_512 = OCSPIssuerMap::new();

        for (i, issuer) in issuers.iter().enumerate() {
            let issuer_name = types::x509_name_to_der(issuer.issuer.subject_name().as_ptr()).unwrap();
            let issuer_key = unsafe {
                let issuer_key_string = super::proto::X509_get0_pubkey_bitstr(issuer.issuer.as_ptr());
                std::slice::from_raw_parts(
                    openssl_sys::ASN1_STRING_get0_data(issuer_key_string.cast()),
                    openssl_sys::ASN1_STRING_length(issuer_key_string.cast()) as usize,
                )
            };

            let issuer_name_sha1 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha1(), &issuer_name,
            ).unwrap().to_vec();
            let issuer_key_sha1 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha1(), &issuer_key,
            ).unwrap().to_vec();
            by_sha1.insert(OCSPIssuerKey {
                name_hash: std::borrow::Cow::Owned(issuer_name_sha1),
                key_hash: std::borrow::Cow::Owned(issuer_key_sha1),
            }, i);

            let issuer_name_sha224 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha224(), &issuer_name,
            ).unwrap().to_vec();
            let issuer_key_sha224 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha224(), &issuer_key,
            ).unwrap().to_vec();
            by_sha224.insert(OCSPIssuerKey {
                name_hash: std::borrow::Cow::Owned(issuer_name_sha224),
                key_hash: std::borrow::Cow::Owned(issuer_key_sha224),
            }, i);

            let issuer_name_sha256 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha256(), &issuer_name,
            ).unwrap().to_vec();
            let issuer_key_sha256 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha256(), &issuer_key,
            ).unwrap().to_vec();
            by_sha256.insert(OCSPIssuerKey {
                name_hash: std::borrow::Cow::Owned(issuer_name_sha256),
                key_hash: std::borrow::Cow::Owned(issuer_key_sha256),
            }, i);

            let issuer_name_sha384 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha384(), &issuer_name,
            ).unwrap().to_vec();
            let issuer_key_sha384 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha384(), &issuer_key,
            ).unwrap().to_vec();
            by_sha384.insert(OCSPIssuerKey {
                name_hash: std::borrow::Cow::Owned(issuer_name_sha384),
                key_hash: std::borrow::Cow::Owned(issuer_key_sha384),
            }, i);

            let issuer_name_sha512 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha512(), &issuer_name,
            ).unwrap().to_vec();
            let issuer_key_sha512 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha512(), &issuer_key,
            ).unwrap().to_vec();
            by_sha512.insert(OCSPIssuerKey {
                name_hash: std::borrow::Cow::Owned(issuer_name_sha512),
                key_hash: std::borrow::Cow::Owned(issuer_key_sha512),
            }, i);

            let issuer_name_sha3_224 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha3_224(), &issuer_name,
            ).unwrap().to_vec();
            let issuer_key_sha3_224 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha3_224(), &issuer_key,
            ).unwrap().to_vec();
            by_sha3_224.insert(OCSPIssuerKey {
                name_hash: std::borrow::Cow::Owned(issuer_name_sha3_224),
                key_hash: std::borrow::Cow::Owned(issuer_key_sha3_224),
            }, i);

            let issuer_name_sha3_256 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha3_256(), &issuer_name,
            ).unwrap().to_vec();
            let issuer_key_sha3_256 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha3_256(), &issuer_key,
            ).unwrap().to_vec();
            by_sha3_256.insert(OCSPIssuerKey {
                name_hash: std::borrow::Cow::Owned(issuer_name_sha3_256),
                key_hash: std::borrow::Cow::Owned(issuer_key_sha3_256),
            }, i);

            let issuer_name_sha3_384 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha3_384(), &issuer_name,
            ).unwrap().to_vec();
            let issuer_key_sha3_384 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha3_384(), &issuer_key,
            ).unwrap().to_vec();
            by_sha3_384.insert(OCSPIssuerKey {
                name_hash: std::borrow::Cow::Owned(issuer_name_sha3_384),
                key_hash: std::borrow::Cow::Owned(issuer_key_sha3_384),
            }, i);

            let issuer_name_sha3_512 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha3_512(), &issuer_name,
            ).unwrap().to_vec();
            let issuer_key_sha3_512 = openssl::hash::hash(
                openssl::hash::MessageDigest::sha3_512(), &issuer_key,
            ).unwrap().to_vec();
            by_sha3_512.insert(OCSPIssuerKey {
                name_hash: std::borrow::Cow::Owned(issuer_name_sha3_512),
                key_hash: std::borrow::Cow::Owned(issuer_key_sha3_512),
            }, i);
        }

        InnerOCSPIssuers {
            by_sha1,
            by_sha224,
            by_sha256,
            by_sha384,
            by_sha512,
            by_sha3_224,
            by_sha3_256,
            by_sha3_384,
            by_sha3_512,
        }
    }
}