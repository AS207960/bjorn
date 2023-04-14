use std::convert::TryFrom;
use base64::prelude::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct FlattenedJWS {
    pub payload: String,
    pub protected: String,
    pub signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JWSProtectedHeader {
    pub alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    #[serde(flatten)]
    pub key: JWKKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub b64: Option<bool>,
}


#[derive(Debug, Deserialize, Serialize)]
pub enum JWKKey {
    #[serde(rename = "kid")]
    KID(String),
    #[serde(rename = "jwk")]
    JWK(JWK)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JWK {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(flatten)]
    pub params: JWKType
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum JWKType {
    EC {
        crv: String,
        x: String,
        y: String,
    },
    RSA {
        n: String,
        e: String,
    },
    OKP {
        crv: String,
        x: String,
        #[serde(default)]
        d: Option<String>
    }
}

impl TryFrom<&openssl::pkey::PKey<openssl::pkey::Public>> for JWK {
    type Error = String;

    fn try_from(from: &openssl::pkey::PKey<openssl::pkey::Public>) -> Result<Self, Self::Error> {
        let (kty, params) = match from.id() {
            openssl::pkey::Id::EC => {
                let ec_key = from.ec_key().unwrap();

                let crv = match ec_key.group().curve_name() {
                    Some(openssl::nid::Nid::SECP256K1) => "P-256",
                    Some(openssl::nid::Nid::SECP384R1) => "P-384",
                    Some(openssl::nid::Nid::SECP521R1) => "P-521",
                    _ => return Err("Unknown curve".to_string()),
                }.to_string();

                let pubkey = ec_key.public_key();
                let mut ctx = openssl::bn::BigNumContext::new().unwrap();
                let mut x = openssl::bn::BigNum::new().unwrap();
                let mut y = openssl::bn::BigNum::new().unwrap();
                pubkey.affine_coordinates_gfp(ec_key.group(), &mut x, &mut y, &mut ctx).unwrap();

                ("EC", JWKType::EC {
                    crv,
                    x: BASE64_URL_SAFE_NO_PAD.encode(x.to_vec()),
                    y: BASE64_URL_SAFE_NO_PAD.encode(y.to_vec()),
                })
            },
            openssl::pkey::Id::RSA => {
                let rsa_key = from.rsa().unwrap();

                ("RSA", JWKType::RSA {
                    n: BASE64_URL_SAFE_NO_PAD.encode(rsa_key.n().to_vec()),
                    e: BASE64_URL_SAFE_NO_PAD.encode(rsa_key.e().to_vec()),
                })
            },
            _ => unimplemented!()
        };

        Ok(JWK {
            kty: kty.to_string(),
            params,
            kid: None,
            alg: None
        })
    }
}

impl TryFrom<&JWK> for openssl::pkey::PKey<openssl::pkey::Public> {
    type Error = String;

    fn try_from(from: &JWK) -> Result<Self, Self::Error> {
        match from.kty.as_str() {
            "EC" => {
                match &from.params {
                    JWKType::EC { crv, x, y } => {
                        let ec_group = match crv.as_str() {
                            "P-256" => openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1).unwrap(),
                            "P-384" => openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap(),
                            "P-521" => openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP521R1).unwrap(),
                            o => return Err(format!("'{}' is not a supported curve", o))
                        };
                        let x = match BASE64_URL_SAFE_NO_PAD.decode(x) {
                            Ok(v) => v,
                            Err(err) => return Err(format!("Invalid x parameter: {}", err))
                        };
                        let y = match BASE64_URL_SAFE_NO_PAD.decode(y) {
                            Ok(v) => v,
                            Err(err) => return Err(format!("Invalid y parameter: {}", err))
                        };
                        let x = match openssl::bn::BigNum::from_slice(&x) {
                            Ok(v) => v,
                            Err(err) => return Err(format!("Invalid n parameter: {}", err))
                        };
                        let y = match openssl::bn::BigNum::from_slice(&y) {
                            Ok(v) => v,
                            Err(err) => return Err(format!("Invalid e parameter: {}", err))
                        };
                        let key = match openssl::ec::EcKey::from_public_key_affine_coordinates(&ec_group, &x, &y) {
                            Ok(v) => v,
                            Err(err) => return Err(format!("Invalid public key: {}", err))
                        };
                        Ok(openssl::pkey::PKey::from_ec_key(key).unwrap())
                    },
                     _ => Err("Invalid key parameters".to_string())
                }
            },
            "RSA" => match &from.params {
                JWKType::RSA { n, e } => {
                    let n = match BASE64_URL_SAFE_NO_PAD.decode(n) {
                        Ok(v) => v,
                        Err(err) => return Err(format!("Invalid n parameter: {}", err))
                    };
                    let e = match BASE64_URL_SAFE_NO_PAD.decode(e) {
                        Ok(v) => v,
                        Err(err) => return Err(format!("Invalid e parameter: {}", err))
                    };
                    let n = match openssl::bn::BigNum::from_slice(&n) {
                        Ok(v) => v,
                        Err(err) => return Err(format!("Invalid n parameter: {}", err))
                    };
                    let e = match openssl::bn::BigNum::from_slice(&e) {
                        Ok(v) => v,
                        Err(err) => return Err(format!("Invalid e parameter: {}", err))
                    };
                    let key = match openssl::rsa::Rsa::from_public_components(n, e) {
                        Ok(v) => v,
                        Err(err) => return Err(format!("Invalid public key: {}", err))
                    };
                    Ok(openssl::pkey::PKey::from_rsa(key).unwrap())
                },
                _ => Err("Invalid key parameters".to_string())
            },
            o => Err(format!("'{}' is not a supported key type", o))
        }
    }
}