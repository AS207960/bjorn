#![allow(incomplete_features)]
#![feature(decl_macro)]
#![feature(unsized_locals)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;

#[derive(Deserialize)]
struct OCSPIssuerConfig {
    issuer_cert_file: String,
    signer_pkcs12_file: String,
    grpc_uri: String,
    cert_id: String,
}

fn main() {
    pretty_env_logger::init();

    rocket::ignite()
        .attach(rocket::fairing::AdHoc::on_attach("OCSP Issuer Config", |rocket| {
            let issuers_conf = rocket.config()
                .get_slice("ocsp_issuers")
                .expect("'ocsp_issuers' not configured");

            let issuers = issuers_conf.iter()
                .map(|i| {
                    let issuer = i.to_owned().try_into::<OCSPIssuerConfig>().expect("Invalid OCSP issuer");
                    let issuer_cert = openssl::x509::X509::from_pem(
                        &std::fs::read(issuer.issuer_cert_file).expect("Unable to read issuer certificate")
                    ).expect("Unable to parse issuer certificate");
                    let signer = openssl::pkcs12::Pkcs12::from_der(
                        &std::fs::read(issuer.signer_pkcs12_file).expect("Unable to read signing keys")
                    ).expect("Unable to parse signing keys").parse("").expect("Unable to parse signing keys");

                    let ocsp_client = bjorn::ocsp::processing::BlockingOCSPClient::connect(issuer.grpc_uri)
                        .expect("Unable to connect to upstream CA");

                    bjorn::ocsp::OCSPIssuer::new(
                        issuer_cert,
                        signer,
                        ocsp_client,
                        issuer.cert_id,
                    )
                })
                .collect::<Vec<_>>();

            Ok(rocket.manage(bjorn::ocsp::OCSPIssuers::new(issuers)))
        }))
        .mount("/", routes![
            bjorn::ocsp::index,
            bjorn::ocsp::ocsp_head,
            bjorn::ocsp::ocsp_get,
            bjorn::ocsp::ocsp_post,
        ])
        .launch();
}