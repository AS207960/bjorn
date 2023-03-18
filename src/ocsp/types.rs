use super::proto;

use chrono::prelude::*;
use foreign_types::ForeignTypeRef;

lazy_static! {
    static ref MD2_WITH_RSA_ENCRYPTION: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.2").unwrap();
    static ref MD5_WITH_RSA_ENCRYPTION: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.4").unwrap();
    static ref SHA1_WITH_RSA_ENCRYPTION: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.5").unwrap();
    static ref DSA_WITH_SHA1: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.10040.4.3").unwrap();
    static ref DSA_WITH_SHA224: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.3.1").unwrap();
    static ref DSA_WITH_SHA256: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.3.2").unwrap();
    static ref ECDSA_WITH_SHA1: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.1").unwrap();
    static ref ECDSA_WITH_SHA224: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.1").unwrap();
    static ref ECDSA_WITH_SHA256: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.2").unwrap();
    static ref ECDSA_WITH_SHA384: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.3").unwrap();
    static ref ECDSA_WITH_SHA512: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.4").unwrap();
    static ref SHA256_WITH_RSA_ENCRYPTION: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.14").unwrap();
    static ref SHA224_WITH_RSA_ENCRYPTION: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.11").unwrap();
    static ref SHA384_WITH_RSA_ENCRYPTION: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.12").unwrap();
    static ref SHA512_WITH_RSA_ENCRYPTION: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.13").unwrap();

    static ref ID_MD2: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.113549.2.2").unwrap();
    static ref ID_MD5: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.2.840.113549.2.5").unwrap();
    static ref ID_SHA1: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.14.3.2.26").unwrap();
    static ref ID_SHA224: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.4").unwrap();
    static ref ID_SHA256: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.1").unwrap();
    static ref ID_SHA384: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.2").unwrap();
    static ref ID_SHA512: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.3").unwrap();
    static ref ID_SHA512_224: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.5").unwrap();
    static ref ID_SHA512_256: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.6").unwrap();
    static ref ID_SHA3_224: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.7").unwrap();
    static ref ID_SHA3_256: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.8").unwrap();
    static ref ID_SHA3_384: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.9").unwrap();
    static ref ID_SHA3_512: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.10").unwrap();

    static ref ID_PKIX_OCSP_BASIC: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.1").unwrap();
    static ref ID_PKIX_OCSP_NONCE: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.2").unwrap();
    static ref ID_PKIX_OCSP_CRL: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.3").unwrap();
    static ref ID_PKIX_OCSP_RESPONSE: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.4").unwrap();
    static ref ID_PKIX_OCSP_NOCHECK: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.5").unwrap();
    static ref ID_PKIX_OCSP_ARCHIVE_CUTOFF: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.6").unwrap();
    static ref ID_PKIX_OCSP_SERVICE_LOCATOR: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.7").unwrap();
    static ref ID_PKIX_OCSP_PREF_SIG_ALGS: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.8").unwrap();
    static ref ID_PKIX_OCSP_EXTENDED_REVOKE: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.9").unwrap();

    static ref ID_CE_INVALIDITY_DATE: asn1::ObjectIdentifier = asn1::ObjectIdentifier::from_string("2.5.29.24").unwrap();
}

#[derive(Debug)]
pub struct OCSPRequest<'a> {
    pub signed_bytes: &'a [u8],
    pub request: TBSRequest<'a>,
    pub signature: Option<Signature<'a>>,
}

#[derive(Debug)]
pub struct Signature<'a> {
    pub algorithm: SignatureAlgorithm,
    pub signature_bytes: &'a [u8],
    pub certs: Vec<openssl::x509::X509>,
}

#[derive(Debug)]
pub struct TBSRequest<'a> {
    pub requester_name: Option<GeneralName>,
    pub requests: Vec<Request<'a>>,
    pub nonce: Option<&'a [u8]>,
    pub acceptable_responses: Option<Vec<OCSPResponseTypeTag>>,
}

#[derive(Debug)]
pub struct Request<'a> {
    pub cert_id: CertID<'a>,
    pub service_locator: Option<ServiceLocator>,
}

#[derive(Clone)]
pub struct CertID<'a> {
    pub hash_algorithm: HashAlgorithm,
    pub issuer_name_hash: &'a [u8],
    pub issuer_key_hash: &'a [u8],
    pub serial_number: &'a [u8],
}

impl std::fmt::Debug for CertID<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("CertID")
            .field("hash_algorithm", &self.hash_algorithm)
            .field("issuer_name_hash", &hex::encode(&self.issuer_name_hash))
            .field("issuer_key_hash", &hex::encode(&self.issuer_key_hash))
            .field("serial_number", &hex::encode(&self.serial_number))
            .finish()
    }
}

#[derive(Debug)]
pub struct ServiceLocator {
    pub issuer: X509Name,
    pub locator: Vec<AccessDescription>,
}

#[derive(Debug)]
pub struct AccessDescription {
    pub method: Asn1Object,
    pub location: GeneralName,
}

#[derive(Debug)]
pub struct OCSPResponse<'a> {
    pub status: OCSPResponseStatus,
    pub response: Option<OCSPResponseType<'a>>,
}

#[derive(Debug, Copy, Clone)]
pub enum OCSPResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

#[derive(Debug)]
pub enum OCSPResponseType<'a> {
    BasicResponse(BasicOCSPResponse<'a>)
}

#[derive(Debug, Eq, PartialEq)]
pub enum OCSPResponseTypeTag {
    BasicResponse,
}

#[derive(Debug)]
pub struct BasicOCSPResponse<'a> {
    pub produced_at: DateTime<Utc>,
    pub issuer: &'a super::issuers::OCSPIssuer,
    pub responses: Vec<SingleOCSPResponse<'a>>,
    pub nonce: Option<&'a [u8]>,
}

#[derive(Debug)]
pub struct SingleOCSPResponse<'a> {
    pub cert_id: CertID<'a>,
    pub cert_status: CertStatus,
    pub this_update: DateTime<Utc>,
    pub next_update: Option<DateTime<Utc>>,
    pub archive_cutoff: Option<DateTime<Utc>>,
    pub invalidity_date: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub enum CertStatus {
    Good,
    Unknown,
    Revoked(RevokedInfo),
}

#[derive(Debug)]
pub struct RevokedInfo {
    pub revocation_time: DateTime<Utc>,
    pub revocation_reason: Option<RevocationReason>
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AACompromise = 10,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashAlgorithm {
    MD2,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl HashAlgorithm {
    fn oid(&self) -> asn1::ObjectIdentifier {
        match self {
            Self::MD2 => ID_MD2.clone(),
            Self::MD5 => ID_MD5.clone(),
            Self::SHA1 => ID_SHA1.clone(),
            Self::SHA224 => ID_SHA224.clone(),
            Self::SHA256 => ID_SHA256.clone(),
            Self::SHA384 => ID_SHA384.clone(),
            Self::SHA512 => ID_SHA512.clone(),
            Self::SHA512_224 => ID_SHA512_224.clone(),
            Self::SHA512_256 => ID_SHA512_256.clone(),
            Self::SHA3_224 => ID_SHA3_224.clone(),
            Self::SHA3_256 => ID_SHA3_256.clone(),
            Self::SHA3_384 => ID_SHA3_384.clone(),
            Self::SHA3_512 => ID_SHA3_512.clone(),
        }
    }

    fn from_oid(oid: &asn1::ObjectIdentifier) -> Option<HashAlgorithm> {
        if oid.eq(&ID_MD2) {
            Some(HashAlgorithm::MD2)
        } else if oid.eq(&ID_MD5) {
            Some(HashAlgorithm::MD2)
        } else if oid.eq(&ID_SHA1) {
            Some(HashAlgorithm::SHA1)
        } else if oid.eq(&ID_SHA224) {
            Some(HashAlgorithm::SHA224)
        } else if oid.eq(&ID_SHA256) {
            Some(HashAlgorithm::SHA256)
        } else if oid.eq(&ID_SHA384) {
            Some(HashAlgorithm::SHA384)
        } else if oid.eq(&ID_SHA512) {
            Some(HashAlgorithm::SHA512)
        } else if oid.eq(&ID_SHA512_224) {
            Some(HashAlgorithm::SHA512_224)
        } else if oid.eq(&ID_SHA512_256) {
            Some(HashAlgorithm::SHA512_256)
        } else if oid.eq(&ID_SHA3_224) {
            Some(HashAlgorithm::SHA3_224)
        } else if oid.eq(&ID_SHA3_256) {
            Some(HashAlgorithm::SHA3_256)
        } else if oid.eq(&ID_SHA3_384) {
            Some(HashAlgorithm::SHA3_384)
        } else if oid.eq(&ID_SHA3_512) {
            Some(HashAlgorithm::SHA3_512)
        } else {
            None
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    RsaWithMd2,
    RsaWithMd5,
    RsaWithSha1,
    RsaWithSha224,
    RsaWithSha256,
    RsaWithSha384,
    RsaWithSha512,
    DsaWithSha1,
    DsaWithSha224,
    DsaWithSha256,
    EcdsaWithSha1,
    EcdsaWithSha224,
    EcdsaWithSha256,
    EcdsaWithSha384,
    EcdsaWithSha512,
}

impl SignatureAlgorithm {
    fn from_oid(oid: &asn1::ObjectIdentifier) -> Option<SignatureAlgorithm> {
        if oid.eq(&MD2_WITH_RSA_ENCRYPTION) {
            Some(SignatureAlgorithm::RsaWithMd2)
        } else if oid.eq(&MD5_WITH_RSA_ENCRYPTION) {
            Some(SignatureAlgorithm::RsaWithMd5)
        } else if oid.eq(&SHA1_WITH_RSA_ENCRYPTION) {
            Some(SignatureAlgorithm::RsaWithSha1)
        } else if oid.eq(&SHA224_WITH_RSA_ENCRYPTION) {
            Some(SignatureAlgorithm::RsaWithSha224)
        } else if oid.eq(&SHA256_WITH_RSA_ENCRYPTION) {
            Some(SignatureAlgorithm::RsaWithSha256)
        } else if oid.eq(&SHA384_WITH_RSA_ENCRYPTION) {
            Some(SignatureAlgorithm::RsaWithSha384)
        } else if oid.eq(&SHA512_WITH_RSA_ENCRYPTION) {
            Some(SignatureAlgorithm::RsaWithSha512)
        } else if oid.eq(&SHA512_WITH_RSA_ENCRYPTION) {
            Some(SignatureAlgorithm::RsaWithSha512)
        } else if oid.eq(&DSA_WITH_SHA1) {
            Some(SignatureAlgorithm::DsaWithSha1)
        } else if oid.eq(&DSA_WITH_SHA224) {
            Some(SignatureAlgorithm::DsaWithSha224)
        } else if oid.eq(&DSA_WITH_SHA256) {
            Some(SignatureAlgorithm::DsaWithSha256)
        } else if oid.eq(&ECDSA_WITH_SHA1) {
            Some(SignatureAlgorithm::EcdsaWithSha1)
        } else if oid.eq(&ECDSA_WITH_SHA224) {
            Some(SignatureAlgorithm::EcdsaWithSha1)
        } else if oid.eq(&ECDSA_WITH_SHA256) {
            Some(SignatureAlgorithm::EcdsaWithSha256)
        } else if oid.eq(&ECDSA_WITH_SHA384) {
            Some(SignatureAlgorithm::EcdsaWithSha384)
        } else if oid.eq(&ECDSA_WITH_SHA512) {
            Some(SignatureAlgorithm::EcdsaWithSha512)
        } else {
            None
        }
    }
}

pub struct GeneralName(openssl::x509::GeneralName);

impl std::fmt::Debug for GeneralName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(d) = self.directory_name() {
            std::fmt::Debug::fmt(d, formatter)
        } else if let Some(o) = self.asn1_obj() {
            std::fmt::Debug::fmt(o, formatter)
        } else {
            std::fmt::Debug::fmt(self.0.as_ref(), formatter)
        }
    }
}

impl GeneralName {
    fn directory_name(&self) -> Option<&openssl::x509::X509NameRef> {
        unsafe {
            if (*self.0.as_ptr()).type_ != openssl_sys::GEN_DIRNAME {
                return None;
            }

            Some(openssl::x509::X509NameRef::from_ptr((*self.0.as_ptr()).d as *mut _))
        }
    }

    fn asn1_obj(&self) -> Option<&openssl::asn1::Asn1ObjectRef> {
        unsafe {
            if (*self.0.as_ptr()).type_ != openssl_sys::GEN_RID {
                return None;
            }

            Some(openssl::asn1::Asn1ObjectRef::from_ptr((*self.0.as_ptr()).d as *mut _))
        }
    }

    fn from_der(der: &[u8]) -> Result<Self, openssl::error::ErrorStack> {
        unsafe {
            openssl_sys::init();
            let len = std::cmp::min(der.len(), libc::c_long::MAX as usize) as libc::c_long;
            Ok(Self(foreign_types::ForeignType::from_ptr(
                crate::util::cvt_p(proto::d2i_GENERAL_NAME(std::ptr::null_mut(), &mut der.as_ptr(), len))?
            )))
        }
    }
}

pub struct X509Name(pub openssl::x509::X509Name);

pub fn x509_name_to_der(name: *mut openssl_sys::X509_NAME) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    unsafe {
        let len = crate::util::cvt(proto::i2d_X509_NAME(name, std::ptr::null_mut()))?;
        let mut buf = vec![0; len as usize];
        crate::util::cvt(proto::i2d_X509_NAME(name, &mut buf.as_mut_ptr()))?;
        Ok(buf)
    }
}

impl std::fmt::Debug for X509Name {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0.as_ref(), formatter)
    }
}

impl X509Name {
    fn from_der(der: &[u8]) -> Result<Self, openssl::error::ErrorStack> {
        unsafe {
            openssl_sys::init();
            let len = std::cmp::min(der.len(), libc::c_long::MAX as usize) as libc::c_long;
            Ok(Self(foreign_types::ForeignType::from_ptr(
                crate::util::cvt_p(proto::d2i_X509_NAME(std::ptr::null_mut(), &mut der.as_ptr(), len))?
            )))
        }
    }
}

pub struct Asn1Object(openssl::asn1::Asn1Object);

impl std::fmt::Debug for Asn1Object {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0.as_ref(), formatter)
    }
}

impl Asn1Object {
    fn from_der(der: &[u8]) -> Result<Self, openssl::error::ErrorStack> {
        unsafe {
            openssl_sys::init();
            let len = std::cmp::min(der.len(), libc::c_long::MAX as usize) as libc::c_long;
            Ok(Self(foreign_types::ForeignType::from_ptr(
                crate::util::cvt_p(proto::d2i_ASN1_OBJECT(std::ptr::null_mut(), &mut der.as_ptr(), len))?
            )))
        }
    }
}

pub fn parse_ocsp_req(req: &[u8]) -> Result<OCSPRequest<'_>, OCSPResponse> {
    let outer_request = match asn1::parse_single::<proto::OCSPRequest>(req) {
        Ok(r) => r,
        Err(e) => {
            warn!("Error parsing OCSP request: {:?}", e);
            return Err(OCSPResponse {
                status: OCSPResponseStatus::MalformedRequest,
                response: None,
            });
        }
    };
    let tbs_request = match outer_request.tbs_request.parse::<proto::TBSRequest>() {
        Ok(r) => r,
        Err(e) => {
            warn!("Error parsing OCSP request: {:?}", e);
            return Err(OCSPResponse {
                status: OCSPResponseStatus::MalformedRequest,
                response: None,
            });
        }
    };

    if tbs_request.version != proto::Version::V1 as u8 {
        warn!("Received unsupported OCSP request version: {}", tbs_request.version);
        return Err(OCSPResponse {
            status: OCSPResponseStatus::MalformedRequest,
            response: None,
        });
    }

    let requester_name = tbs_request.requester_name.map(|n| {
        let der = n.full_data();
        GeneralName::from_der(der)
    }).transpose().map_err(|e: openssl::error::ErrorStack| {
        warn!("Error parsing OCSP request: {:?}", e);
        OCSPResponse {
            status: OCSPResponseStatus::MalformedRequest,
            response: None,
        }
    })?;

    let signature = outer_request.signature.map(|s| {
        Ok(Signature {
            algorithm: SignatureAlgorithm::from_oid(&s.signature_algorithm.algorithm).ok_or_else(|| {
                warn!("Unknown signature algorithm: {:?}", s.signature_algorithm.algorithm);
                OCSPResponse {
                    status: OCSPResponseStatus::MalformedRequest,
                    response: None,
                }
            })?,
            signature_bytes: s.signature.as_bytes(),
            certs: match s.certs {
                Some(c) => c.map(|d| {
                    openssl::x509::X509::from_der(d.full_data())
                }).collect::<Result<Vec<_>, openssl::error::ErrorStack>>().map_err(|e| {
                    warn!("Error parsing OCSP request: {:?}", e);
                    OCSPResponse {
                        status: OCSPResponseStatus::MalformedRequest,
                        response: None,
                    }
                })?,
                None => vec![]
            },
        })
    }).transpose()?;

    let mut nonce = None;
    let mut acceptable_responses = None;

    if let Some(exts) = tbs_request.request_extensions {
        for ext in exts {
            if ext.extension_id.eq(&ID_PKIX_OCSP_NONCE) {
                let nonce_bytes = match asn1::parse_single::<&[u8]>(ext.extension_value) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Error parsing OCSP request: {:?}", e);
                        return Err(OCSPResponse {
                            status: OCSPResponseStatus::MalformedRequest,
                            response: None,
                        });
                    }
                };
                nonce = Some(nonce_bytes)
            } else if ext.extension_id.eq(&ID_PKIX_OCSP_RESPONSE) {
                let resp_oids = match asn1::parse_single::<proto::AcceptableResponses>(ext.extension_value) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Error parsing OCSP request: {:?}", e);
                        return Err(OCSPResponse {
                            status: OCSPResponseStatus::MalformedRequest,
                            response: None,
                        });
                    }
                };
                acceptable_responses = Some(resp_oids.filter_map(|o| if o.eq(&ID_PKIX_OCSP_BASIC) {
                    Some(OCSPResponseTypeTag::BasicResponse)
                } else {
                    None
                }).collect());
            } else if ext.critical {
                warn!("Unsupported critical request extension: {:?}", ext.extension_id);
                return Err(OCSPResponse {
                    status: OCSPResponseStatus::MalformedRequest,
                    response: None,
                });
            }
        }
    }

    let requests = tbs_request.request_list.map(|mut r| {
        let mut service_locator = None;

        if let Some(ref mut exts) = r.single_request_extensions {
            for ext in exts {
                if ext.extension_id.eq(&ID_PKIX_OCSP_SERVICE_LOCATOR) {
                    let locator_proto = match asn1::parse_single::<proto::ServiceLocator>(ext.extension_value) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("Error parsing OCSP request: {:?}", e);
                            return Err(OCSPResponse {
                                status: OCSPResponseStatus::MalformedRequest,
                                response: None,
                            });
                        }
                    };
                    service_locator = Some(match (|| -> Result<_, openssl::error::ErrorStack> {
                        Ok(ServiceLocator {
                            issuer: X509Name::from_der(locator_proto.issuer.full_data())?,
                            locator: locator_proto.locator.map(|l| Ok(AccessDescription {
                                method: Asn1Object::from_der(l.access_method.full_data())?,
                                location: GeneralName::from_der(l.access_location.full_data())?,
                            })).collect::<Result<_, _>>()?,
                        })
                    })() {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("Error parsing OCSP request: {:?}", e);
                            return Err(OCSPResponse {
                                status: OCSPResponseStatus::MalformedRequest,
                                response: None,
                            });
                        }
                    });
                } else if ext.critical {
                    warn!("Unsupported critical single request extension: {:?}", ext.extension_id);
                    return Err(OCSPResponse {
                        status: OCSPResponseStatus::MalformedRequest,
                        response: None,
                    });
                }
            }
        }

        Ok(Request {
            service_locator,
            cert_id: CertID {
                hash_algorithm: HashAlgorithm::from_oid(&r.request_cert.hash_algorithm.id).ok_or_else(|| {
                    warn!("Unknown digest algorithm: {:?}", r.request_cert.hash_algorithm.id);
                    OCSPResponse {
                        status: OCSPResponseStatus::MalformedRequest,
                        response: None,
                    }
                })?,
                issuer_name_hash: r.request_cert.issuer_name_hash,
                issuer_key_hash: r.request_cert.issuer_key_hash,
                serial_number: r.request_cert.serial_number.as_bytes(),
            },
        })
    }).collect::<Result<Vec<_>, _>>()?;

    Ok(OCSPRequest {
        signed_bytes: outer_request.tbs_request.data(),
        request: TBSRequest {
            requester_name,
            nonce,
            acceptable_responses,
            requests,
        },
        signature,
    })
}


pub fn serialize_ocsp_resp(resp: &OCSPResponse) -> Vec<u8> {
    let response_bytes = resp.response.as_ref().map(|r| match r {
        OCSPResponseType::BasicResponse(br) => {
            let mut certs = vec![br.issuer.signer.cert.as_ref().expect("No signing cert").to_der().unwrap()];
            if let Some(chain) = &br.issuer.signer.ca {
                for chain_cert in chain.iter() {
                    certs.push(chain_cert.to_der().unwrap());
                }
            }
            let certs_tlv = certs.iter()
                .map(|c| asn1::parse_single::<asn1::Tlv>(&c).unwrap())
                .collect::<Vec<_>>();

            let mut extensions = vec![proto::ExtensionWrite {
                extension_id: ID_PKIX_OCSP_EXTENDED_REVOKE.clone(),
                extension_value: proto::CowBytes(std::borrow::Cow::Owned(asn1::write_single(&()).unwrap())),
                critical: false,
            }];

            if let Some(nonce_ext) = br.nonce {
                extensions.push(proto::ExtensionWrite {
                    extension_id: ID_PKIX_OCSP_NONCE.clone(),
                    extension_value: proto::CowBytes(std::borrow::Cow::Owned(asn1::write_single(&nonce_ext).unwrap())),
                    critical: false,
                });
            }

            let responses = br.responses.iter().map(|sr| {
                let mut single_extensions = vec![];

                if let Some(archive_cutoff) = sr.archive_cutoff {
                    single_extensions.push(proto::ExtensionWrite {
                        extension_id: ID_PKIX_OCSP_ARCHIVE_CUTOFF.clone(),
                        extension_value: proto::CowBytes(std::borrow::Cow::Owned(
                            asn1::write_single(&asn1::GeneralizedTime::new(archive_cutoff).unwrap()).unwrap()
                        )),
                        critical: false,
                    })
                }

                if let Some(invalidity_date) = sr.invalidity_date {
                    single_extensions.push(proto::ExtensionWrite {
                        extension_id: ID_CE_INVALIDITY_DATE.clone(),
                        extension_value: proto::CowBytes(std::borrow::Cow::Owned(
                            asn1::write_single(&asn1::GeneralizedTime::new(invalidity_date).unwrap()).unwrap()
                        )),
                        critical: false,
                    })
                }

                proto::SingleResponse {
                    cert_id: proto::CertID {
                        hash_algorithm: proto::DigestAlgorithmIdentifier {
                            id: sr.cert_id.hash_algorithm.oid(),
                            parameters: None,
                        },
                        issuer_name_hash: sr.cert_id.issuer_name_hash,
                        issuer_key_hash: &sr.cert_id.issuer_key_hash,
                        serial_number: asn1::BigUint::new(&sr.cert_id.serial_number).unwrap(),
                    },
                    cert_status: match &sr.cert_status {
                        CertStatus::Good => proto::CertStatus::Good(()),
                        CertStatus::Revoked(r) => proto::CertStatus::Revoked(proto::RevokedInfo {
                            revocation_time: asn1::GeneralizedTime::new(r.revocation_time).unwrap(),
                            revocation_reason: r.revocation_reason.map(|reason| proto::Enumerated::new(reason as u32)),
                        }),
                        CertStatus::Unknown => proto::CertStatus::Unknown(()),
                    },
                    this_update: asn1::GeneralizedTime::new(sr.this_update).unwrap(),
                    next_update: sr.next_update.map(|n| asn1::GeneralizedTime::new(n).unwrap()),
                    single_extensions: if single_extensions.is_empty() {
                        None
                    } else {
                        Some(proto::CowSequenceOfWriter(std::borrow::Cow::Owned(single_extensions)))
                    },
                }
            }).collect::<Vec<_>>();

            let tbs_response_data = proto::ResponseData {
                version: proto::Version::V1 as u8,
                responder_id: proto::ResponderID::ByHash(&br.issuer.pub_key_sha1),
                produced_at: asn1::GeneralizedTime::new(br.produced_at).unwrap(),
                responses: proto::CowSequenceOfWriter(std::borrow::Cow::Owned(responses)),
                response_extensions: if extensions.is_empty() {
                    None
                } else {
                    Some(proto::CowSequenceOfWriter(std::borrow::Cow::Owned(extensions)))
                },
            };

            let tbs_response_bytes = asn1::write_single(&tbs_response_data).unwrap();
            let (sig_alg, message_digest) = match br.issuer.signer.pkey.as_ref().expect("No signing key").id() {
                openssl::pkey::Id::RSA => (SHA512_WITH_RSA_ENCRYPTION.clone(), openssl::hash::MessageDigest::sha512()),
                openssl::pkey::Id::DSA => (DSA_WITH_SHA256.clone(), openssl::hash::MessageDigest::sha256()),
                openssl::pkey::Id::EC => (ECDSA_WITH_SHA512.clone(), openssl::hash::MessageDigest::sha512()),
                _ => unimplemented!()
            };
            let mut signer = openssl::sign::Signer::new(message_digest, &br.issuer.signer.pkey.as_ref().unwrap()).unwrap();
            let signature = signer.sign_oneshot_to_vec(&tbs_response_bytes).unwrap();

            (ID_PKIX_OCSP_BASIC.clone(), asn1::write_single(&proto::BasicOCSPResponse {
                tbs_response_data,
                signature_algorithm: proto::SignatureAlgorithmIdentifier {
                    algorithm: sig_alg,
                    parameters: None,
                },
                signature: proto::BitStringWritable {
                    value: &signature,
                },
                certs: Some(proto::CowSequenceOfWriter(std::borrow::Cow::Owned(certs_tlv))),
            }).unwrap())
        }
    });

    let out_resp = proto::OCSPResponse {
        response_status: asn1::Enumerated::new(resp.status as u32),
        response_bytes: match response_bytes {
            Some((o, r)) => Some(proto::ResponseBytes {
                response_type: o,
                response: proto::CowBytes(std::borrow::Cow::Owned(r)),
            }),
            _ => None,
        },
    };

    asn1::write_single(&out_resp).unwrap()
}