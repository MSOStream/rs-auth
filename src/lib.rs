use serde::{Deserialize, Serialize};
#[macro_use]
extern crate lazy_static;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    exp: i64,
}

lazy_static! {
    static ref JWTSECRET: String = env::var("JWTSECRET").unwrap();
}

#[macro_export]
macro_rules! is_logged_in {
    ($req: expr) => {{
        use jsonwebtoken::decode;
        use jsonwebtoken::{DecodingKey, Algorithm, Validation};
        use std::env;
        use rs_auth::Claims;

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

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
