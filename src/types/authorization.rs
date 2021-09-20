use chrono::prelude::*;

#[derive(Serialize)]
pub struct Authorization {
    pub identifier: super::identifier::Identifier,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    pub challenges: Vec<super::challenge::Challenge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<bool>
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Status {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "invalid")]
    Invalid,
    #[serde(rename = "invalid")]
    Deactivated,
    #[serde(rename = "expired")]
    Expired,
    #[serde(rename = "revoked")]
    Revoked,
}

impl Default for Status {
    fn default() -> Status {
        Status::Pending
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorizationUpdate {
    #[serde(default)]
    pub status: Option<Status>,
}