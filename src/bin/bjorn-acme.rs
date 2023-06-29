#[macro_use]
extern crate rocket;

#[launch]
fn rocket() -> _ {
    pretty_env_logger::init();
    info!("Bjorn ACME Server version {} starting up...", env!("CARGO_PKG_VERSION"));

    rocket::build()
        .attach(bjorn::acme::ConfigFairing())
        .attach(bjorn::DBConn::fairing())
        .attach(bjorn::acme::DBMigrationFairing())
        .attach( rocket_dyn_templates::Template::fairing())
        .attach(rocket::fairing::AdHoc::try_on_ignite("gRPC Config", |rocket| async move {
            let dst = rocket.figment()
                .extract_inner::<String>("ca_grpc_uri")
                .expect("'ca_grpc_uri' not configured");

            let order_client = bjorn::acme::processing::OrderClient::connect(dst).await
                .expect("Unable to connect to upstream CA");

            Ok(rocket.manage(order_client))
        }))
        .register("/", catchers![
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
}