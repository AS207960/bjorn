#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Type {
    DNS,
    IP,
    Email,
}

impl Type {
    pub fn from_str(id_type: &str) -> Option<Self> {
        match id_type {
            "dns" => Some(Self::DNS),
            "ip" => Some(Self::IP),
            "email" => Some(Self::Email),
            _ => None
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Self::DNS => "dns".to_string(),
            Self::IP => "ip".to_string(),
            Self::Email => "email".to_string(),
        }
    }
}