#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

use std::net::ToSocketAddrs;

#[derive(Deserialize)]
struct ValidatorConfig {
    caa_identities: Vec<String>,
    tor_storage: Option<std::path::PathBuf>
}

fn main() {
    pretty_env_logger::init();

    let fig = rocket::config::Config::figment();
    let config = fig.extract::<rocket::config::Config>().expect("Unable to load config");

    let rt = tokio::runtime::Runtime::new().expect("failed to obtain a new Runtime object");

    let conf = fig.extract::<ValidatorConfig>().expect("Unable to load validator config");
    let serve_addr = (config.address, config.port).to_socket_addrs()
        .expect("Invalid listen address").next().unwrap();

    let validator = rt.block_on(match conf.tor_storage {
        Some(s) => {
            let s =  rt.block_on(torrosion::storage::FileStorage::new(s)).expect("Unable to initialize Tor storage");
            bjorn::validator::Validator::new(conf.caa_identities, Some(s))
        },
        None => bjorn::validator::Validator::new(conf.caa_identities, None)
    });

    let server_future = tonic::transport::Server::builder()
                        .add_service(bjorn::cert_order::validator_server::ValidatorServer::new(validator))
                        .serve(serve_addr);
    info!("Listening for requests on {}", serve_addr);
    rt.block_on(server_future).expect("failed to successfully run the future on Runtime");
}