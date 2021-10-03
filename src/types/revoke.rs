#[derive(Debug, Deserialize)]
pub struct RevokeCert {
    pub certificate: String,
    pub reason: Option<u32>,
}