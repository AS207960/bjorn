use chrono::prelude::*;

#[derive(Serialize)]
pub struct List {
    pub orders: Vec<String>
}

#[derive(Serialize, Deserialize)]
pub struct Order {
    #[serde(skip_deserializing)]
    pub status: Status,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    pub identifiers: Vec<super::identifier::Identifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub error: Option<super::error::Error>,
    #[serde(skip_deserializing)]
    pub authorizations: Vec<String>,
    #[serde(skip_deserializing)]
    pub finalize: String,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub enum Status {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "processing")]
    Processing,
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "invalid")]
    Invalid,
}

impl Default for Status {
    fn default() -> Status {
        Status::Pending
    }
}

#[derive(Debug, Deserialize)]
pub struct OrderCreate {
    pub identifiers: Vec<super::identifier::Identifier>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct OrderFinalize {
    pub csr: String,
}