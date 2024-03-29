#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_derive_enum;
#[macro_use]
extern crate diesel_migrations;

pub(crate) mod types;
pub(crate) mod util;
//pub(crate) mod iodef;
pub mod acme;
pub mod ocsp;
pub mod validator;

pub mod cert_order {
    tonic::include_proto!("cert_order");
}

#[rocket_sync_db_pools::database("db")]
pub struct DBConn(pub diesel::PgConnection);