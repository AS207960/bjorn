use super::schema::*;
use diesel::prelude::*;
use base64::prelude::*;
use futures::StreamExt;

#[derive(Insertable, Queryable, Identifiable, Debug)]
#[diesel(primary_key(nonce), table_name = nonces)]
pub struct Nonce {
    pub nonce: uuid::Uuid,
    pub issued_at: chrono::DateTime<chrono::Utc>,
}

#[derive(DbEnum, Debug, PartialEq, Eq)]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Insertable, Queryable, Identifiable, Debug)]
#[diesel(table_name = accounts)]
pub struct Account {
    pub id: uuid::Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub tos_agreed_at: chrono::DateTime<chrono::Utc>,
    pub status: AccountStatus,
    pub public_key: Vec<u8>,
    pub eab_id: Option<String>,
    pub eab_protected_header: Option<String>,
    pub eab_payload: Option<String>,
    pub eab_sig: Option<String>,
}

#[derive(DbEnum, Debug)]
pub enum AccountContactType {
    Email
}

#[derive(Insertable, Queryable, Identifiable, Debug)]
#[diesel(table_name = account_contacts)]
pub struct AccountContact {
    pub id: uuid::Uuid,
    pub account: uuid::Uuid,
    pub contact_type: AccountContactType,
    pub contact_value: String,
}

impl Account {
    pub fn kid(&self) -> String {
        rocket::uri!(crate::acme::account(crate::util::uuid_as_b64(&self.id))).to_string()
    }

    pub(crate) async fn to_json(
        &self, db: &crate::DBConn, external_uri: &crate::acme::ExternalURL,
    ) -> crate::acme::ACMEResult<crate::types::account::Account> {
        let id = self.id.clone();
        let account_contacts: Vec<AccountContact> = crate::try_db_result!(db.run(move |c| super::schema::account_contacts::dsl::account_contacts.filter(
            super::schema::account_contacts::dsl::account.eq(&id)
        ).load(c)).await, "Failed to get account contacts: {}")?;

        Ok(crate::types::account::Account {
            status: match self.status {
                AccountStatus::Valid => crate::types::account::Status::Valid,
                AccountStatus::Deactivated => crate::types::account::Status::Deactivated,
                AccountStatus::Revoked => crate::types::account::Status::Revoked,
            },
            contact: account_contacts.into_iter().map(|c| match c.contact_type {
                AccountContactType::Email => format!("mailto:{}", c.contact_value)
            }).collect(),
            terms_of_service_agreed: true,
            external_account_binding: match &self.eab_payload {
                None => None,
                Some(p) => Some(crate::types::jose::FlattenedJWS {
                    protected: self.eab_protected_header.as_deref().unwrap_or_default().to_string(),
                    payload: p.to_string(),
                    signature: self.eab_sig.as_deref().unwrap_or_default().to_string(),
                })
            },
            orders: external_uri.0.join(
                &rocket::uri!(crate::acme::account_orders(crate::util::uuid_as_b64(&self.id))).to_string()
            ).unwrap().to_string(),
        })
    }
}

pub(crate) fn parse_contact(contact: &str) -> Result<(AccountContactType, String), (crate::types::error::Type, String)> {
    let url = match url::Url::parse(contact) {
        Ok(v) => v,
        Err(_) => return Err((crate::types::error::Type::InvalidContact, "Invalid URL formatting".to_string()))
    };
    match url.scheme() {
        "mailto" => {
            if url.query().is_some() {
                return Err((crate::types::error::Type::InvalidContact, "hfields not allowed in mailto URL".to_string()));
            }
            let path = url.path();
            if path.contains(",") {
                return Err((crate::types::error::Type::InvalidContact, "No more than one address per URL allowed".to_string()));
            }
            Ok((AccountContactType::Email, path.to_string()))
        }
        _ => return Err((crate::types::error::Type::UnsupportedContact, "Unsupported URL scheme".to_string()))
    }
}

pub(crate) fn parse_contacts(contacts: &[&str], account_id: &uuid::Uuid) -> crate::acme::ACMEResult<Vec<AccountContact>> {
    let mut contact_objs = vec![];

    for contact in contacts {
        let (contact_type, contact_value) = match parse_contact(&contact) {
            Ok(v) => v,
            Err((error_type, detail)) => {
                return Err(crate::types::error::Error {
                    error_type,
                    status: 400,
                    title: "Invalid contact".to_string(),
                    detail,
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                });
            }
        };
        contact_objs.push(AccountContact {
            id: uuid::Uuid::new_v4(),
            account: account_id.clone(),
            contact_type,
            contact_value,
        });
    }

    Ok(contact_objs)
}

#[derive(Insertable, Queryable, Identifiable, Debug)]
#[diesel(table_name = orders)]
pub struct Order {
    pub id: uuid::Uuid,
    pub account: uuid::Uuid,
    pub ca_id: Vec<u8>,
}

impl Order {
    pub fn url(&self) -> String {
        rocket::uri!(crate::acme::order(crate::util::uuid_as_b64(&self.id))).to_string()
    }

    pub(crate) async fn to_json(
        &self, db: &crate::DBConn, ca_obj: crate::cert_order::Order, external_uri: &crate::acme::ExternalURL
    ) -> crate::acme::ACMEResult<crate::types::order::Order> {
        let acct = self.account;
        let authorizations = futures::stream::iter(ca_obj.authorizations.into_iter()).then(|a| async move {
            let a1 = a.clone();
            let a = match crate::try_db_result!(db.run(move |c| super::schema::authorizations::dsl::authorizations.filter(
                super::schema::authorizations::dsl::ca_id.eq(&a1).and(
                    super::schema::authorizations::dsl::account.eq(&acct)
                )
            ).first::<super::models::Authorization>(c).optional()).await, "Failed to look for existing authorization: {}")? {
                Some(a) => a,
                None => {
                    let a = Authorization {
                        id: uuid::Uuid::new_v4(),
                        account: self.account.clone(),
                        ca_id: a,
                    };
                    let a = crate::try_db_result!(db.run(move |c| diesel::insert_into(super::schema::authorizations::dsl::authorizations)
                        .values(&a)
                        .get_result(c)).await, "Failed to insert authorization: {}")?;
                    a
                }
            };

            Ok(external_uri.0.join(&a.url()).unwrap().to_string())
        }).collect::<Vec<_>>().await.into_iter().collect::<Result<Vec<_>, _>>()?;

        let cert = match ca_obj.certificate_id {
            Some(i) => {
                let i1 = i.clone();
                Some(match crate::try_db_result!(db.run(move |c| super::schema::certificates::dsl::certificates.filter(
                    super::schema::certificates::dsl::ca_id.eq(&i1)
                ).first::<super::models::Certificate>(c).optional()).await, "Failed to look for existing certificate: {}")? {
                    Some(c) => c,
                    None => {
                        let c = Certificate {
                            id: uuid::Uuid::new_v4(),
                            ca_id: i,
                        };
                        let c = crate::try_db_result!(db.run(move |o| diesel::insert_into(super::schema::certificates::dsl::certificates)
                        .values(&c)
                        .get_result(o)).await, "Failed to insert certificate: {}")?;
                        c
                    }
                })
            },
            None => None,
        };

        Ok(crate::types::order::Order {
            status: match crate::cert_order::OrderStatus::from_i32(ca_obj.status) {
                Some(crate::cert_order::OrderStatus::OrderPending) => crate::types::order::Status::Pending,
                Some(crate::cert_order::OrderStatus::OrderReady) => crate::types::order::Status::Ready,
                Some(crate::cert_order::OrderStatus::OrderValid) => crate::types::order::Status::Valid,
                Some(crate::cert_order::OrderStatus::OrderInvalid) => crate::types::order::Status::Invalid,
                Some(crate::cert_order::OrderStatus::OrderProcessing) => crate::types::order::Status::Processing,
                None => return Err(crate::internal_server_error!())
            },
            expires: crate::util::proto_to_chrono(ca_obj.expires),
            identifiers: ca_obj.identifiers.into_iter().map(super::processing::map_rpc_identifier).collect(),
            not_before: crate::util::proto_to_chrono(ca_obj.not_before),
            not_after: crate::util::proto_to_chrono(ca_obj.not_after),
            error: None,
            authorizations,
            finalize: external_uri.0.join(
                &rocket::uri!(crate::acme::order_finalize(crate::util::uuid_as_b64(&self.id))).to_string()
            ).unwrap().to_string(),
            certificate: cert.map(|c| external_uri.0.join(&c.url()).unwrap().to_string()),
        })
    }
}

#[derive(Insertable, Queryable, Identifiable, Debug)]
#[diesel(table_name = authorizations)]
pub struct Authorization {
    pub id: uuid::Uuid,
    pub account: uuid::Uuid,
    pub ca_id: Vec<u8>,
}

impl Authorization {
    pub fn url(&self) -> String {
        rocket::uri!(crate::acme::authorization(crate::util::uuid_as_b64(&self.id))).to_string()
    }

    pub(crate) fn to_json(
        &self, ca_obj: crate::cert_order::Authorization, external_uri: &crate::acme::ExternalURL
    ) -> crate::acme::ACMEResult<crate::types::authorization::Authorization> {
        Ok(crate::types::authorization::Authorization {
            identifier: super::processing::map_rpc_identifier(
                crate::try_db_result!(ca_obj.identifier.ok_or("identifier not set"), "Invalid authorization: {}")?
            ),
            status: match crate::cert_order::AuthorizationStatus::from_i32(ca_obj.status) {
                Some(crate::cert_order::AuthorizationStatus::AuthorizationPending) => crate::types::authorization::Status::Pending,
                Some(crate::cert_order::AuthorizationStatus::AuthorizationInvalid) => crate::types::authorization::Status::Invalid,
                Some(crate::cert_order::AuthorizationStatus::AuthorizationValid) => crate::types::authorization::Status::Valid,
                Some(crate::cert_order::AuthorizationStatus::AuthorizationDeactivated) => crate::types::authorization::Status::Deactivated,
                Some(crate::cert_order::AuthorizationStatus::AuthorizationExpired) => crate::types::authorization::Status::Expired,
                Some(crate::cert_order::AuthorizationStatus::AuthorizationRevoked) => crate::types::authorization::Status::Revoked,
                None => return Err(crate::internal_server_error!())
            },
            expires: crate::util::proto_to_chrono(ca_obj.expires),
            challenges: ca_obj.challenges.into_iter().map(|c| self.challenge_to_json(c, external_uri)).collect::<Result<_, _>>()?,
            wildcard: ca_obj.wildcard,
        })
    }

    pub(crate) fn challenge_to_json(
        &self, ca_obj: crate::cert_order::Challenge, external_uri: &crate::acme::ExternalURL,
    ) -> crate::acme::ACMEResult<crate::types::challenge::Challenge> {
        Ok(crate::types::challenge::Challenge {
            challenge_type: match crate::cert_order::ChallengeType::from_i32(ca_obj.r#type) {
                Some(crate::cert_order::ChallengeType::ChallengeHttp01) => crate::types::challenge::Type::HTTP01,
                Some(crate::cert_order::ChallengeType::ChallengeDns01) => crate::types::challenge::Type::DNS01,
                Some(crate::cert_order::ChallengeType::ChallengeTlsalpn01) => crate::types::challenge::Type::TLSALPN01,
                Some(crate::cert_order::ChallengeType::ChallengeOnionCsr01) => crate::types::challenge::Type::OnionCSR01,
                None => return Err(crate::internal_server_error!())
            },
            url: external_uri.0.join(&rocket::uri!(crate::acme::challenge(
                crate::util::uuid_as_b64(&self.id),
                BASE64_URL_SAFE_NO_PAD.encode(ca_obj.id)
            )).to_string()).unwrap().to_string(),
            status: match crate::cert_order::ChallengeStatus::from_i32(ca_obj.status) {
                Some(crate::cert_order::ChallengeStatus::ChallengePending) => crate::types::challenge::Status::Pending,
                Some(crate::cert_order::ChallengeStatus::ChallengeProcessing) => crate::types::challenge::Status::Processing,
                Some(crate::cert_order::ChallengeStatus::ChallengeValid) => crate::types::challenge::Status::Valid,
                Some(crate::cert_order::ChallengeStatus::ChallengeInvalid) => crate::types::challenge::Status::Invalid,
                None => return Err(crate::internal_server_error!())
            },
            validated: crate::util::proto_to_chrono(ca_obj.validated),
            error: ca_obj.error.and_then(|errors| crate::util::error_list_to_result(
                errors.errors.into_iter().map(crate::acme::processing::rpc_error_to_problem).collect(),
                "Multiple errors make this challenge invalid".to_string(),
            ).err()),
            token: ca_obj.token,
            auth_key: if ca_obj.auth_key.len() == 0 {
                None
            } else {
                Some(crate::types::jose::JWK {
                    kty: "OKP".to_string(),
                    kid: None,
                    alg: None,
                    params: crate::types::jose::JWKType::OKP {
                        crv: "Ed25519".to_string(),
                        x: BASE64_URL_SAFE_NO_PAD.encode(ca_obj.auth_key),
                        d: None
                    }
                })
            },
            nonce: if ca_obj.nonce.len() == 0 {
                None
            } else {
                Some(BASE64_URL_SAFE_NO_PAD.encode(ca_obj.nonce))
            },
        })
    }
}

#[derive(Insertable, Queryable, Identifiable, Debug)]
#[diesel(table_name = certificates)]
pub struct Certificate {
    pub id: uuid::Uuid,
    pub ca_id: Vec<u8>,
}

impl Certificate {
    pub fn url(&self) -> String {
        rocket::uri!(crate::acme::certificate(cid = crate::util::uuid_as_b64(&self.id), idx = _, cidx = _)).to_string()
    }
}

#[derive(Insertable, Queryable, Identifiable, Debug)]
#[diesel(table_name = tos_agreement_tokens)]
pub struct ToSAgreementToken {
    pub id: uuid::Uuid,
    pub account: uuid::Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}