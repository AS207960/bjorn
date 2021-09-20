#![allow(incomplete_features)]
#![feature(decl_macro)]
#![feature(unsized_locals)]

#[macro_use]
extern crate log;

use std::net::ToSocketAddrs;

fn main() {
    pretty_env_logger::init();

    let config = rocket::config::RocketConfig::read()
        .expect("Unable to read config").active().clone();

    let rt = tokio::runtime::Runtime::new().expect("failed to obtain a new Runtime object");

    let caa_identities = match config.get_slice("caa_identities") {
        Ok(v) => v.iter().map(|i| match i.as_str() {
            Some(i) => i.to_string(),
            None => panic!("Unable to load CAA identities from config: array value not a string"),
        }).collect::<Vec<_>>(),
        Err(e) => {
            panic!("Unable to load CAA identities from config: {}", e);
        }
    };
    let serve_addr = (config.address, config.port).to_socket_addrs()
        .expect("Invalid listen address").next().unwrap();

    let validator = bjorn::validator::Validator::new(caa_identities);

    let server_future = tonic::transport::Server::builder()
                        .add_service(bjorn::cert_order::validator_server::ValidatorServer::new(validator))
                        .serve(serve_addr);
    info!("Listening for requests on {}", serve_addr);
    rt.block_on(server_future).expect("failed to successfully run the future on Runtime");
}