use chrono::prelude::*;
use base64::prelude::*;

mod proto;
mod types;
pub mod processing;
pub(crate) mod issuers;

pub use issuers::{OCSPIssuers, OCSPIssuer};

const HOME_PAGE: &'static str = include_str!("index.html");

pub struct OCSPResponse {
    value: Vec<u8>,
    produced_at: Option<DateTime<Utc>>,
    next_update: Option<DateTime<Utc>>,
}

impl<'r> rocket::response::Responder<'r, 'static> for OCSPResponse {
    fn respond_to(self, _req: &'r rocket::request::Request<'_>) -> rocket::response::Result<'static> {
        let mut builder = rocket::response::Response::build();

        builder.header(rocket::http::ContentType::new("application", "ocsp-response"));
        builder.raw_header("Date", Utc::now().to_rfc2822());
        builder.raw_header("Cache-Control", "public, no-transform, must-revalidate");

        let etag = hex::encode(openssl::hash::hash(
            openssl::hash::MessageDigest::sha1(), &self.value,
        ).unwrap());
        builder.raw_header("ETag", etag);

        if let Some(produced_at) = self.produced_at {
            builder.raw_header("Last-Modified", produced_at.to_rfc2822());
        }
        if let Some(next_update) = self.next_update {
            builder.raw_header("Expires", next_update.to_rfc2822());
        }

        builder.sized_body(self.value.len(), std::io::Cursor::new(self.value));

        builder.ok()
    }
}

impl From<types::OCSPResponse<'_>> for OCSPResponse {
    fn from(from: types::OCSPResponse) -> OCSPResponse {
        let (produced_at, next_update) = from.response.as_ref()
            .map_or((None, None), |r| match r {
                types::OCSPResponseType::BasicResponse(br) => {
                    let mut next_updates = br.responses.iter().filter_map(|r| r.next_update).collect::<Vec<_>>();
                    next_updates.sort_unstable();

                    (Some(br.produced_at), if next_updates.is_empty() {
                        None
                    } else {
                        Some(next_updates.remove(0))
                    })
                }
            });

        OCSPResponse {
            value: types::serialize_ocsp_resp(&from),
            produced_at,
            next_update,
        }
    }
}

#[get("/")]
pub fn index() -> rocket::response::content::RawHtml<&'static str> {
    rocket::response::content::RawHtml(HOME_PAGE)
}

#[head("/<_request>")]
pub fn ocsp_head(_request: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[get("/<request>")]
pub fn ocsp_get(request: String, ocsp_issuers: &rocket::State<issuers::OCSPIssuers<'_>>) -> Result<OCSPResponse, rocket::http::Status> {
    let ocsp_req = match BASE64_URL_SAFE.decode(&request) {
        Ok(r) => r,
        Err(_) => return Err(rocket::http::Status::BadRequest)
    };

    Ok(processing::handle_ocsp(&ocsp_req, &ocsp_issuers).into())
}

#[post("/", format = "application/ocsp-request", data = "<request>")]
pub async fn ocsp_post(request: rocket::data::Data<'_>, ocsp_issuers: &rocket::State<issuers::OCSPIssuers<'_>>) -> Result<OCSPResponse, rocket::http::Status> {
    const LIMIT: usize = 4096;

    let ocsp_req = match request.open(LIMIT * rocket::data::ByteUnit::B).into_bytes().await {
        Ok(r) => r,
        Err(_) => return Err(rocket::http::Status::InternalServerError)
    };

    if !ocsp_req.is_complete() {
        return Err(rocket::http::Status::PayloadTooLarge);
    }

    Ok(processing::handle_ocsp(&ocsp_req, &ocsp_issuers).into())
}