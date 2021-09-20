#[derive(Debug, Serialize)]
pub struct Account {
    pub status: Status,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed")]
    pub terms_of_service_agreed: bool,
    #[serde(rename = "externalAccountBinding")]
    pub external_account_binding: Option<super::jose::FlattenedJWS>,
    pub orders: String,
}

#[derive(Debug, Deserialize)]
pub struct AccountCreate {
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed", default)]
    pub terms_of_service_agreed: bool,
    #[serde(rename = "externalAccountBinding", default)]
    pub external_account_binding: Option<super::jose::FlattenedJWS>,
    #[serde(rename = "onlyReturnExisting", default)]
    pub only_return_existing: bool,
}

#[derive(Debug, Deserialize)]
pub struct AccountUpdate {
    #[serde(default)]
    pub contact: Option<Vec<String>>,
    // #[serde(rename = "externalAccountBinding", default)]
    // pub external_account_binding: Option<super::jose::FlattenedJWS>,
    #[serde(default)]
    pub status: Option<Status>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Status {
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "deactivated")]
    Deactivated,
    #[serde(rename = "revoked")]
    Revoked
}

impl Default for Status {
    fn default() -> Status {
        Status::Valid
    }
}

#[derive(Debug, Deserialize)]
pub struct KeyChange {
    pub account: String,
    pub old_key: super::jose::JWK,
}