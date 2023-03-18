use crate::types;
use diesel::prelude::*;

lazy_static! {
    static ref NONCES: std::sync::Mutex<std::collections::HashSet<uuid::Uuid>> = std::sync::Mutex::new(std::collections::HashSet::new());
}

#[derive(Debug)]
pub struct ReplayNonce<R> {
    nonce: String,
    responder: R
}

impl<R> ReplayNonce<R> {
    pub async fn new_nonce(db: &crate::DBConn, responder: R) -> Result<Self, rocket::http::Status> {
        let new_nonce = super::models::Nonce {
            nonce: uuid::Uuid::new_v4(),
            issued_at: chrono::Utc::now(),
        };
        let nonce = match db.run(move |c| diesel::insert_into(super::schema::nonces::table)
            .values(&new_nonce)
            .get_result::<super::models::Nonce>(c)).await {
            Err(err) => {
                error!("Error inserting new nonce: {}", err);
                return Err(rocket::http::Status::InternalServerError);
            }
            Ok(v) => v,
        };

        let nonce = crate::util::uuid_as_b64(&nonce.nonce);

        Ok(Self {
            nonce,
            responder
        })
    }
}

impl<'r, 'a: 'r, R: rocket::response::Responder<'r, 'a>> rocket::response::Responder<'r, 'a> for ReplayNonce<R> {
    fn respond_to(self, request: &'r rocket::request::Request<'_>) -> rocket::response::Result<'a> {
        let mut result = self.responder.respond_to(request)?;
        result.set_raw_header("Replay-Nonce", self.nonce);
        Ok(result)
    }
}

pub(crate) async fn verify_nonce(nonce: &str, db: &crate::DBConn) -> crate::acme::ACMEResult<()> {
    let nonce_uuid = match crate::util::b64_to_uuid(&nonce) {
        Some(v) => v,
        None => {
            return Err(types::error::Error {
                error_type: types::error::Type::BadNonce,
                status: 400,
                title: "Bad nonce".to_string(),
                detail: "Invalid nonce format".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }
    };

    let affected = match db.run(move |c| diesel::delete(super::schema::nonces::dsl::nonces.filter(
        super::schema::nonces::dsl::nonce.eq(&nonce_uuid))
    ).execute(c)).await {
        Ok(v) => v,
        Err(err) => {
            error!("Error checking nonce validitiy: {}", err);
            return Err(crate::internal_server_error!());
        }
    };

    if affected < 1 {
        return Err(types::error::Error {
            error_type: types::error::Type::BadNonce,
            status: 400,
            title: "Bad nonce".to_string(),
            detail: "The nonce may have expired or it is being reused.".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }
    Ok(())
}