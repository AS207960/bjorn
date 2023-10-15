#[derive(Serialize)]
pub struct Directory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount", skip_serializing_if = "Option::is_none")]
    pub new_account: Option<String>,
    #[serde(rename = "newOrder", skip_serializing_if = "Option::is_none")]
    pub new_order: Option<String>,
    #[serde(rename = "newAuthz", skip_serializing_if = "Option::is_none")]
    pub new_authz: Option<String>,
    #[serde(rename = "revokeCert", skip_serializing_if = "Option::is_none")]
    pub revoke_cert: Option<String>,
    #[serde(rename = "keyChange", skip_serializing_if = "Option::is_none")]
    pub key_change: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>
}

#[derive(Serialize)]
pub struct Meta {
    #[serde(rename = "termsOfService", skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(rename = "caaIdentities", skip_serializing_if = "Vec::is_empty")]
    pub caa_identities: Vec<String>,
    #[serde(rename = "externalAccountRequired", skip_serializing_if = "Option::is_none")]
    pub external_account_required: Option<bool>,
    #[serde(rename = "inBandOnionCAARequired", skip_serializing_if = "Option::is_none")]
    pub in_band_onion_caa_required: Option<bool>
}