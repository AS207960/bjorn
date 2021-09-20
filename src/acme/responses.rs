use crate::types;

#[derive(Debug)]
pub struct Headers<R> {
    pub responder: R,
    pub headers: Vec<(String, String)>,
}

impl<'r, R: rocket::response::Responder<'r>> rocket::response::Responder<'r> for Headers<R> {
    fn respond_to(self, request: &rocket::request::Request<'_>) -> rocket::response::Result<'r> {
        let mut result = self.responder.respond_to(request)?;
        for header in self.headers {
            result.set_raw_header(header.0, header.1);
        }
        Ok(result)
    }
}

pub enum InnerACMEResponse<'r, R: rocket::response::Responder<'r>> {
    Ok((R, rocket::http::Status)),
    Error(rocket_contrib::json::Json<types::error::Error>),
    _Phantom(std::convert::Infallible, std::marker::PhantomData<&'r R>,),
}

impl<'r, R: rocket::response::Responder<'r>> rocket::response::Responder<'r> for InnerACMEResponse<'r, R> {
    fn respond_to(self, request: &rocket::request::Request<'_>) -> rocket::response::Result<'r> {
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

pub type ACMEResponse<'r, R> = super::replay::ReplayNonce<super::links::LinksHeaders<InnerACMEResponse<'r, R>>>;

impl<'r, R: rocket::response::Responder<'r>> ACMEResponse<'r, R> {
    pub fn new(r: InnerACMEResponse<'r, R>, mut extra_links: Vec<super::links::LinkHeader>) -> ACMEResponse<'r, R> {
        extra_links.push(super::links::LinkHeader {
            url: super::DIRECTORY_URI.to_string(),
            relative: true,
            relation: "index".to_string(),
        });
        super::replay::ReplayNonce(super::links::LinksHeaders {
            responder: r,
            links: extra_links,
        })
    }

    pub fn new_error(err: types::error::Error) -> ACMEResponse<'r, R> {
        ACMEResponse::new(InnerACMEResponse::Error(rocket_contrib::json::Json(err)), vec![])
    }
}