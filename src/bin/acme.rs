#![allow(incomplete_features)]
#![feature(decl_macro)]
#![feature(unsized_locals)]

#[macro_use]
extern crate rocket;

fn main() {
    pretty_env_logger::init();

    rocket::ignite()
        .attach(bjorn::acme::ConfigFairing())
        .attach(bjorn::DBConn::fairing())
        .attach(bjorn::acme::DBMigrationFairing())
        .attach(rocket_contrib::templates::Template::fairing())
        .attach(rocket::fairing::AdHoc::on_attach("gRPC Config", |rocket| {
            let dst = rocket.config()
                .get_string("ca_grpc_uri")
                .expect("'ca_grpc_uri' not configured");

            let order_client = bjorn::acme::processing::BlockingOrderClient::connect(dst)
                .expect("Unable to connect to upstream CA");

            Ok(rocket.manage(order_client))
        }))
        .register(catchers![
            bjorn::acme::acme_401,
            bjorn::acme::acme_404,
            bjorn::acme::acme_405,
            bjorn::acme::acme_415,
            bjorn::acme::acme_422,
            bjorn::acme::acme_500,
        ])
        .mount("/", routes![
            bjorn::acme::index,
            bjorn::acme::tos_agree,
            bjorn::acme::tos_agree_post,
            bjorn::acme::directory,
            bjorn::acme::directory_post,
            bjorn::acme::get_nonce,
            bjorn::acme::get_nonce_post,
            bjorn::acme::new_account,
            bjorn::acme::new_account_post,
            bjorn::acme::account,
            bjorn::acme::account_post,
            bjorn::acme::key_change,
            bjorn::acme::key_change_post,
            bjorn::acme::account_orders,
            bjorn::acme::account_orders_post,
            bjorn::acme::new_order,
            bjorn::acme::new_order_post,
            bjorn::acme::new_authz,
            bjorn::acme::new_authz_post,
            bjorn::acme::order,
            bjorn::acme::order_post,
            bjorn::acme::order_finalize,
            bjorn::acme::order_finalize_post,
            bjorn::acme::authorization,
            bjorn::acme::authorization_post,
            bjorn::acme::challenge,
            bjorn::acme::challenge_post,
            bjorn::acme::certificate,
            bjorn::acme::certificate_post,
            bjorn::acme::revoke,
            bjorn::acme::revoke_post,
        ])
        .launch();
}