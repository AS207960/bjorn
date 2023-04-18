extern "C" {
    pub fn d2i_ASN1_OBJECT(
        a: *mut *mut openssl_sys::ASN1_OBJECT,
        pp: *mut *const libc::c_uchar,
        length: libc::c_long,
    ) -> *mut openssl_sys::ASN1_OBJECT;

    pub fn d2i_X509_NAME(
        a: *mut *mut openssl_sys::X509_NAME,
        pp: *mut *const libc::c_uchar,
        length: libc::c_long,
    ) -> *mut openssl_sys::X509_NAME;

    pub fn i2d_X509_NAME(
        x: *mut openssl_sys::X509_NAME,
        buf: *mut *mut u8,
    ) -> libc::c_int;

    pub fn d2i_GENERAL_NAME(
        a: *mut *mut openssl_sys::GENERAL_NAME,
        pp: *mut *const libc::c_uchar,
        length: libc::c_long,
    ) -> *mut openssl_sys::GENERAL_NAME;

    pub fn X509_get0_pubkey_bitstr(
        x: *mut openssl_sys::X509
    ) -> *mut openssl_sys::ASN1_BIT_STRING;
}



#[derive(asn1::Asn1Read)]
pub struct OCSPRequest<'a> {
    pub tbs_request: asn1::Tlv<'a>,
    #[explicit(0)]
    pub signature: Option<Signature<'a>>,
}

#[derive(asn1::Asn1Write, Debug)]
pub struct OCSPResponse<'a> {
    pub response_status: asn1::Enumerated,
    #[explicit(0)]
    pub response_bytes: Option<ResponseBytes<'a>>,
}

#[derive(asn1::Asn1Read)]
pub struct TBSRequest<'a> {
    #[explicit(0)]
    #[default(0)]
    pub version: u8,
    #[explicit(1)]
    pub requester_name: Option<asn1::Tlv<'a>>,
    pub request_list: asn1::SequenceOf<'a, Request<'a>>,
    #[explicit(2)]
    pub request_extensions: Option<Extensions<'a>>,
}

pub enum Version {
    V1 = 0
}

#[derive(asn1::Asn1Read)]
pub struct Request<'a> {
    pub request_cert: CertID<'a>,
    #[explicit(0)]
    pub single_request_extensions: Option<Extensions<'a>>
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, Clone)]
pub struct CertID<'a> {
    pub hash_algorithm: DigestAlgorithmIdentifier<'a>,
    pub issuer_name_hash: &'a [u8],
    pub issuer_key_hash: &'a [u8],
    pub serial_number: asn1::BigUint<'a>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write)]
pub struct Signature<'a> {
    pub signature_algorithm: SignatureAlgorithmIdentifier<'a>,
    pub signature: asn1::BitString<'a>,
    #[explicit(0)]
    pub certs: Option<asn1::SequenceOf<'a, asn1::Tlv<'a>>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, Clone)]
pub struct SignatureAlgorithmIdentifier<'a> {
    pub algorithm: asn1::ObjectIdentifier,
    pub parameters: Option<asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read, asn1::Asn1Write, Debug, Clone)]
pub struct DigestAlgorithmIdentifier<'a> {
    pub id: asn1::ObjectIdentifier,
    pub parameters: Option<asn1::Tlv<'a>>,
}

pub type Extensions<'a> = asn1::SequenceOf<'a, Extension<'a>>;
pub type ExtensionsWriter<'a> = CowSequenceOfWriter<'a, ExtensionWrite<'a>>;

#[derive(asn1::Asn1Read, Debug)]
pub struct Extension<'a> {
    pub extension_id: asn1::ObjectIdentifier,
    #[default(false)]
    pub critical: bool,
    pub extension_value: &'a [u8]
}

#[derive(asn1::Asn1Write, Debug, Clone)]
pub struct ExtensionWrite<'a> {
    pub extension_id: asn1::ObjectIdentifier,
    #[default(false)]
    pub critical: bool,
    pub extension_value: CowBytes<'a>
}

#[derive(asn1::Asn1Write, Debug)]
pub struct ResponseBytes<'a> {
    pub response_type: asn1::ObjectIdentifier,
    pub response: CowBytes<'a>
}

#[derive(asn1::Asn1Write)]
pub struct BasicOCSPResponse<'a> {
    pub tbs_response_data: ResponseData<'a>,
    pub signature_algorithm: SignatureAlgorithmIdentifier<'a>,
    pub signature: BitStringWritable<'a>,
    #[explicit(0)]
    pub certs: Option<CowSequenceOfWriter<'a, asn1::Tlv<'a>>>,
}

pub struct BitStringWritable<'a> {
    pub value: &'a [u8]
}

impl<'a> asn1::SimpleAsn1Writable for BitStringWritable<'a> {
    const TAG: asn1::Tag = asn1::Tag::primitive(0x03);

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> Result<(), asn1::WriteError> {
        dest.push_byte(0)?;
        dest.push_slice(self.value)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CowBytes<'a>(pub std::borrow::Cow<'a, [u8]>);

impl<'a> asn1::SimpleAsn1Writable for CowBytes<'a> {
    const TAG: asn1::Tag = asn1::Tag::primitive(0x04);

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> Result<(), asn1::WriteError> {
        dest.push_slice(self.0.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct CowSequenceOfWriter<'a, T>(pub std::borrow::Cow<'a, [T]>) where
    T: asn1::Asn1Writable + ToOwned + Clone;

impl<'a, T> asn1::SimpleAsn1Writable for CowSequenceOfWriter<'a, T>
    where
        T: asn1::Asn1Writable + ToOwned + Clone
{
    const TAG: asn1::Tag = asn1::Tag::primitive(0x10);

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> Result<(), asn1::WriteError> {
        let mut w = asn1::Writer::new(dest);
        for el in self.0.as_ref() {
            w.write_element(el)?;
        }
        Ok(())
    }
}

impl<'a> std::ops::Deref for CowBytes<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

#[derive(asn1::Asn1Write)]
pub struct ResponseData<'a> {
    #[explicit(0)]
    #[default(0)]
    pub version: u8,
    pub responder_id: ResponderID<'a>,
    pub produced_at: asn1::GeneralizedTime,
    pub responses: CowSequenceOfWriter<'a, SingleResponse<'a>>,
    #[explicit(1)]
    pub response_extensions: Option<ExtensionsWriter<'a>>
}

#[derive(asn1::Asn1Write, Debug)]
#[allow(dead_code)]
pub enum ResponderID<'a> {
    #[explicit(1)]
    ByName(&'a [u8]),
    #[explicit(2)]
    ByHash(&'a [u8]),
}

#[derive(asn1::Asn1Write, Clone)]
pub struct SingleResponse<'a> {
    pub cert_id: CertID<'a>,
    pub cert_status: CertStatus,
    pub this_update: asn1::GeneralizedTime,
    #[explicit(0)]
    pub next_update: Option<asn1::GeneralizedTime>,
    #[explicit(1)]
    pub single_extensions: Option<ExtensionsWriter<'a>>
}

#[derive(asn1::Asn1Write, Clone)]
pub enum CertStatus {
    #[implicit(0)]
    Good(()),
    #[implicit(1)]
    Revoked(RevokedInfo),
    #[implicit(2)]
    Unknown(()),
}

#[derive(asn1::Asn1Write, Clone)]
pub struct RevokedInfo {
    pub revocation_time: asn1::GeneralizedTime,
    #[explicit(0)]
    pub revocation_reason: Option<Enumerated>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Enumerated(u32);

impl Enumerated {
    pub fn new(v: u32) -> Enumerated {
        Enumerated(v)
    }

    #[allow(dead_code)]
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl asn1::SimpleAsn1Writable for Enumerated {
    const TAG: asn1::Tag = asn1::Tag::primitive(0x0a);

    fn write_data(&self, dest: &mut asn1::WriteBuf) -> Result<(), asn1::WriteError> {
        u32::write_data(&self.0, dest)
    }
}

pub type AcceptableResponses<'a> = asn1::SequenceOf<'a, asn1::ObjectIdentifier>;

#[derive(asn1::Asn1Read)]
pub struct ServiceLocator<'a> {
    pub issuer: asn1::Tlv<'a>,
    pub locator: asn1::SequenceOf<'a, AccessDescription<'a>>,
}

#[derive(asn1::Asn1Read, Debug)]
pub struct AccessDescription<'a> {
    pub access_method: asn1::Tlv<'a>,
    pub access_location: asn1::Tlv<'a>
}

#[allow(dead_code)]
pub type PreferredSignatureAlgorithms<'a> = asn1::SequenceOf<'a, PreferredSignatureAlgorithm>;

#[derive(asn1::Asn1Read, Debug)]
pub struct PreferredSignatureAlgorithm {
    pub sig_id: asn1::ObjectIdentifier,
    pub cert_id: Option<asn1::ObjectIdentifier>,
}