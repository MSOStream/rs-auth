use chrono::{Duration, Local};
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate lazy_static;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    exp: i64,
}

fn get_exp() -> i64 {
    (Local::now() + Duration::days(1)).timestamp()
}

impl Claims {
    pub fn new(id: String) -> Self {
        Claims {
            sub: id,
            exp: get_exp(),
        }
    }
}

lazy_static! {
    static ref JWTSECRET: String = env::var("JWTSECRET").unwrap();
}

#[macro_export]
macro_rules! is_logged_in {
    ($req: expr) => {{
        use jsonwebtoken::decode;
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};
        use rs_auth::Claims;
        use std::env;

        let mut res = false;

        if let Some(auth) = $req.metadata().get("auth") {
            res = decode::<Claims>(
                auth.to_str().unwrap(),
                &DecodingKey::from_secret(JWTSECRET.as_bytes()),
                &Validation::new(Algorithm::HS256),
            )
            .is_ok();
        }

        res
    }};
}

#[macro_export]
macro_rules! user_id {
    ($req: expr) => {{
        use jsonwebtoken::decode;
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};
        use rs_auth::Claims;
        use std::env;

        let mut res = None;

        if let Some(auth) = $req.metadata().get("auth") {
            res = match decode::<Claims>(
                auth.to_str().unwrap(),
                &DecodingKey::from_secret(JWTSECRET.as_bytes()),
                &Validation::new(Algorithm::HS256),
            ) {
                Ok(jwt) => Some(jwt.claims.sub),
                Err(_) => None,
            }
        }

        res
    }};
}
