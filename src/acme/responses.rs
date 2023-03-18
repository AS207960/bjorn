use crate::types;

#[derive(Debug)]
pub struct Headers<R> {
    pub responder: R,
    pub headers: Vec<(String, String)>,
}

impl<'r, 'a: 'r, R: rocket::response::Responder<'r, 'a>> rocket::response::Responder<'r, 'a> for Headers<R> {
    fn respond_to(self, request: &'r rocket::request::Request<'_>) -> rocket::response::Result<'a> {
        let mut result = self.responder.respond_to(request)?;
        for header in self.headers {
            result.set_raw_header(header.0, header.1);
        }
        Ok(result)
    }
}

pub enum InnerACMEResponse<'r, 'a: 'r, R: rocket::response::Responder<'r, 'a>> {
    Ok((R, rocket::http::Status)),
    Error(rocket::serde::json::Json<types::error::Error>),
    _Phantom1(std::convert::Infallible, std::marker::PhantomData<&'r R>,),
    _Phantom2(std::convert::Infallible, std::marker::PhantomData<&'a R>,),
}

impl<'r, 'a: 'r, R: rocket::response::Responder<'r, 'a> > rocket::response::Responder<'r, 'a> for InnerACMEResponse<'r, 'a, R> {
    fn respond_to(self, request: &'r rocket::request::Request<'_>) -> rocket::response::Result<'a> {
        match self {
            InnerACMEResponse::Ok((r, s)) => {
                let mut res = r.respond_to(request)?;
                res.set_status(s);
                Ok(res)
            },
            InnerACMEResponse::Error(e) => {
                let status = rocket::http::Status::from_code(e.status).unwrap_or(rocket::http::Status::InternalServerError);
                let mut r = e.respond_to(request)?;
                r.set_status(status);
                r.set_raw_header("Content-Type", "application/problem+json");
                Ok(r)
            }
        }
    }
}


pub enum ACMEResponse<'r, 'a, R: rocket::response::Responder<'r, 'a>> {
    Normal(super::replay::ReplayNonce<super::links::LinksHeaders<InnerACMEResponse<'r, 'a, R>>>),
    Raw(InnerACMEResponse<'r, 'a, R>)
}

impl<'r, 'a: 'r, R: rocket::response::Responder<'r, 'a>> rocket::response::Responder<'r, 'a> for ACMEResponse<'r, 'a, R> {
    fn respond_to(self, request: &'r rocket::request::Request<'_>) -> rocket::response::Result<'a> {
        match self {
            ACMEResponse::Normal(r) => r.respond_to(request),
            ACMEResponse::Raw(r) => r.respond_to(request)
        }
    }
}

impl<'r, 'a: 'r, R: rocket::response::Responder<'r, 'a> + 'r + 'a> ACMEResponse<'r, 'a, R> {
    pub async fn new(
        r: InnerACMEResponse<'r, 'a, R>, mut extra_links: Vec<super::links::LinkHeader>,
        db: &crate::DBConn, config: &crate::acme::Config
    ) -> ACMEResponse<'r, 'a, R> {
        extra_links.push(super::links::LinkHeader {
            url: super::DIRECTORY_URI.to_string(),
            relative: true,
            relation: "index".to_string(),
        });
        match super::replay::ReplayNonce::new_nonce(
            db,
            super::links::LinksHeaders::new_links(r, extra_links, config)
        ).await {
            Ok(r) => ACMEResponse::Normal(r),
            Err(e) => {
                error!("Failed to generate nonce: {}", e);
                ACMEResponse::Raw(InnerACMEResponse::Error(rocket::serde::json::Json(crate::internal_server_error!())))
            }
        }
    }

    pub async fn new_error(err: types::error::Error, db: &crate::DBConn, config: &crate::acme::Config) -> ACMEResponse<'r, 'a, R> {
        ACMEResponse::new(InnerACMEResponse::Error(rocket::serde::json::Json(err)), vec![], db, config).await
    }
}