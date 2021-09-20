#[derive(Debug)]
pub struct LinkHeader {
    pub url: String,
    pub relative: bool,
    pub relation: String,
}

#[derive(Debug)]
pub struct LinksHeaders<R> {
    pub responder: R,
    pub links: Vec<LinkHeader>,
}

impl<'r, R: rocket::response::Responder<'r>> rocket::response::Responder<'r> for LinksHeaders<R> {
    fn respond_to(self, request: &rocket::request::Request<'_>) -> rocket::response::Result<'r> {
        let global_config = match request.guard::<rocket::State<crate::acme::Config>>() {
            rocket::request::Outcome::Success(v) => v,
            rocket::request::Outcome::Failure(e) => return Err(e.0),
            rocket::request::Outcome::Forward(_) => unreachable!()
        };
        let mut result = self.responder.respond_to(request)?;
        for link in self.links {
            let url = match link.relative {
                false => link.url,
                true => format!("{}{}", global_config.external_uri, link.url)
            };
            result.adjoin_raw_header("Link", format!("<{}>; rel=\"{}\"", url, link.relation));
        }
        Ok(result)
    }
}