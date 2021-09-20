#[derive(Deserialize, Serialize, Debug)]
pub struct Error {
    #[serde(rename = "type")]
    pub error_type: Type,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(rename = "subproblems", skip_serializing_if = "Vec::is_empty")]
    pub sub_problems: Vec<Error>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<super::identifier::Identifier>
}

#[derive(Deserialize, Serialize, Debug)]
pub enum Type {
    #[serde(rename = "urn:ietf:params:acme:error:accountDoesNotExist")]
    AccountDoesNotExist,
    #[serde(rename = "urn:ietf:params:acme:error:alreadyRevoked")]
    AlreadyRevoked,
    #[serde(rename = "urn:ietf:params:acme:error:badCSR")]
    BadCSR,
    #[serde(rename = "urn:ietf:params:acme:error:badNonce")]
    BadNonce,
    #[serde(rename = "urn:ietf:params:acme:error:badPublicKey")]
    BadPublicKey,
    #[serde(rename = "urn:ietf:params:acme:error:badRevocationReason")]
    BadRevocationReason,
    #[serde(rename = "urn:ietf:params:acme:error:badSignatureAlgorithm")]
    BadSignatureAlgorithm,
    #[serde(rename = "urn:ietf:params:acme:error:caa")]
    CAA,
    #[serde(rename = "urn:ietf:params:acme:error:compound")]
    Compound,
    #[serde(rename = "urn:ietf:params:acme:error:connection")]
    Connection,
    #[serde(rename = "urn:ietf:params:acme:error:dns")]
    DNS,
    #[serde(rename = "urn:ietf:params:acme:error:externalAccountRequired")]
    ExternalAccountRequired,
    #[serde(rename = "urn:ietf:params:acme:error:incorrectResponse")]
    IncorrectResponse,
    #[serde(rename = "urn:ietf:params:acme:error:invalidContact")]
    InvalidContact,
    #[serde(rename = "urn:ietf:params:acme:error:malformed")]
    Malformed,
    #[serde(rename = "urn:ietf:params:acme:error:orderNotReady")]
    OrderNotReady,
    #[serde(rename = "urn:ietf:params:acme:error:rateLimited")]
    RateLimited,
    #[serde(rename = "urn:ietf:params:acme:error:rejectedIdentifier")]
    RejectedIdentifier,
    #[serde(rename = "urn:ietf:params:acme:error:serverInternal")]
    ServerInternal,
    #[serde(rename = "urn:ietf:params:acme:error:tls")]
    TLS,
    #[serde(rename = "urn:ietf:params:acme:error:unauthorized")]
    Unauthorized,
    #[serde(rename = "urn:ietf:params:acme:error:unsupportedContact")]
    UnsupportedContact,
    #[serde(rename = "urn:ietf:params:acme:error:unsupportedIdentifier")]
    UnsupportedIdentifier,
    #[serde(rename = "urn:ietf:params:acme:error:userActionRequired")]
    UserActionRequired,
    #[serde(rename = "urn:ietf:params:acme:error:autoRenewalCanceled")]
    AutoRenewalCanceled,
    #[serde(rename = "urn:ietf:params:acme:error:autoRenewalExpired")]
    AutoRenewalExpired,
    #[serde(rename = "urn:ietf:params:acme:error:autoRenewalCancellationInvalid")]
    AutoRenewalCancellationInvalid,
    #[serde(rename = "urn:ietf:params:acme:error:autoRenewalRevocationNotSupported")]
    AutoRenewalRevocationNotSupported,
}