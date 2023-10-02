#[derive(Debug)]
pub struct LinkHeader {
    pub url: String,
    pub relative: bool,
    pub relation: String,
}

#[derive(Debug)]
pub struct LinksHeaders<R> {
    pub responder: R,
    pub links: Vec<(String, String)>,
}

impl<R> LinksHeaders<R> {
    pub fn new_links(responder: R, links: Vec<LinkHeader>, external_uri: &crate::acme::ExternalURL) -> Self {
        let mut result = vec![];
        for link in links {
            let url = match link.relative {
                false => link.url,
                true => external_uri.0.join(&link.url).unwrap().to_string(),
            };
            result.push((url, link.relation));
        }
        Self {
            responder,
            links: result
        }
    }
}

impl<'r, 'a: 'r, R: rocket::response::Responder<'r, 'a>> rocket::response::Responder<'r, 'a> for LinksHeaders<R> {
    fn respond_to(self, request: &'r rocket::request::Request<'_>) -> rocket::response::Result<'a> {
        let mut result = self.responder.respond_to(request)?;
        for (url, relation) in self.links {
            result.adjoin_raw_header("Link", format!("<{}>; rel=\"{}\"", url, relation));
        }
        Ok(result)
    }
}