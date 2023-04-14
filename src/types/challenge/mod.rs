use chrono::prelude::*;

#[derive(Serialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub challenge_type: Type,
    pub url: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<super::error::Error>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(rename = "authKey", skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<super::jose::JWK>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Type {
    #[serde(rename = "http-01")]
    HTTP01,
    #[serde(rename = "dns-01")]
    DNS01,
    #[serde(rename = "tls-alpn-01")]
    TLSALPN01,
    #[serde(rename = "onion-csr-01")]
    OnionCSR01
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Status {
    #[serde(rename = "pending")]
    Pending,
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


#[derive(Deserialize, Debug)]
pub struct ChallengeRespond {

}