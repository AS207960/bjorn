#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;

use futures::StreamExt;

#[derive(Deserialize)]
struct OCSPIssuerConfig {
    issuer_cert_file: String,
    signer_pkcs12_file: String,
    grpc_uri: String,
    cert_id: String,
}

#[launch]
fn rocket() -> _ {
    pretty_env_logger::init();

    rocket::build()
        .attach( rocket_dyn_templates::Template::fairing())
        .attach(rocket::fairing::AdHoc::try_on_ignite("OCSP Issuer Config", |rocket| async move {
            let issuers_conf = rocket.figment()
                .extract_inner::<Vec<OCSPIssuerConfig>>("ocsp_issuers")
                .expect("'ocsp_issuers' not configured");

            let issuers = futures::stream::iter(issuers_conf.into_iter())
                .then(|issuer| async move{
                    let issuer_cert = openssl::x509::X509::from_pem(
                        &std::fs::read(issuer.issuer_cert_file).expect("Unable to read issuer certificate")
                    ).expect("Unable to parse issuer certificate");
                    let signer = openssl::pkcs12::Pkcs12::from_der(
                        &std::fs::read(issuer.signer_pkcs12_file).expect("Unable to read signing keys")
                    ).expect("Unable to parse signing keys").parse2("").expect("Unable to parse signing keys");

                    let ocsp_client = bjorn::ocsp::processing::OCSPClient::connect(issuer.grpc_uri).await
                        .expect("Unable to connect to upstream CA");

                    bjorn::ocsp::OCSPIssuer::new(
                        issuer_cert,
                        signer,
                        ocsp_client,
                        issuer.cert_id,
                    )
                })
                .collect::<Vec<_>>().await;

            Ok(rocket.manage(bjorn::ocsp::OCSPIssuers::new(issuers)))
        }))
        .mount("/", routes![
            bjorn::ocsp::index,
            bjorn::ocsp::ocsp_head,
            bjorn::ocsp::ocsp_get,
            bjorn::ocsp::ocsp_post,
        ])
}