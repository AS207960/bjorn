#![feature(decl_macro)]
#![feature(exhaustive_patterns)]
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate log;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate diesel_derive_enum;

pub(crate) mod types;
pub(crate) mod util;
pub mod acme;
pub mod ocsp;
pub mod validator;

pub mod cert_order {
    tonic::include_proto!("cert_order");
}

#[database("db")]
pub struct DBConn(pub rocket_contrib::databases::diesel::PgConnection);