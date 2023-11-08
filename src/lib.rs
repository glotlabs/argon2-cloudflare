use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use worker::Context;
use worker::Env;
use worker::Method;
use worker::Request;
use worker::Response;

#[worker::event(fetch)]
async fn main(req: Request, _env: Env, _ctx: Context) -> worker::Result<Response> {
    let result = match (req.method(), req.path().as_ref()) {
        (Method::Post, "/hash") => hash_handler(req).await,
        (Method::Post, "/verify") => verify_handler(req).await,
        _ => Err(Error::InvalidRoute),
    };

    match result {
        Ok(body) => Response::ok(body),
        Err(err) => err.to_response(),
    }
}

// HASH

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashRequest {
    pub password: String,
    pub options: Option<HashOptions>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashOptions {
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashResponse {
    pub hash: String,
}

async fn hash_handler(mut req: Request) -> Result<String, Error> {
    let hash_req: HashRequest = req
        .json()
        .await
        .map_err(|err| Error::DecodeBody(err.to_string()))?;

    let password_hash = hash(&hash_req.password, hash_req.options)?;

    let hash_response = HashResponse {
        hash: password_hash,
    };
    serde_json::to_string(&hash_response).map_err(|err| Error::EncodeBody(err.to_string()))
}

fn hash(password: &str, options: Option<HashOptions>) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = match options {
        Some(opts) => {
            let params = Params::new(opts.memory_cost, opts.time_cost, opts.parallelism, None)
                .map_err(|err| Error::HashOptions(err.to_string()))?;

            Ok(Argon2::new(
                argon2::Algorithm::Argon2id,
                Version::default(),
                params,
            ))
        }

        None => Ok(Argon2::default()),
    }?;

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|password_hash| password_hash.to_string())
        .map_err(|err| Error::Hash(err.to_string()))
}

// VERIFY

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub password: String,
    pub hash: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub matches: bool,
}

async fn verify_handler(mut req: Request) -> Result<String, Error> {
    let options: VerifyRequest = req
        .json()
        .await
        .map_err(|err| Error::DecodeBody(err.to_string()))?;

    let matches = verify(&options)?;
    let verify_response = VerifyResponse { matches };
    serde_json::to_string(&verify_response).map_err(|err| Error::EncodeBody(err.to_string()))
}

fn verify(options: &VerifyRequest) -> Result<bool, Error> {
    let password_hash = PasswordHash::new(&options.hash)
        .map_err(|err| Error::InvalidPasswordHash(err.to_string()))?;

    let argon2 = Argon2::default();

    match argon2.verify_password(options.password.as_bytes(), &password_hash) {
        Ok(()) => Ok(true),

        Err(err) => match err {
            argon2::password_hash::Error::Password => Ok(false),
            _ => Err(Error::Verify(err.to_string())),
        },
    }
}

// ERROR

enum Error {
    InvalidRoute,
    DecodeBody(String),
    EncodeBody(String),
    HashOptions(String),
    Hash(String),
    InvalidPasswordHash(String),
    Verify(String),
}

impl Error {
    fn to_response(&self) -> worker::Result<Response> {
        match self {
            Error::InvalidRoute => Response::error("Route not found", 404),
            Error::DecodeBody(err) => {
                Response::error(format!("Failed to decode request body: {}", err), 400)
            }
            Error::EncodeBody(err) => {
                Response::error(format!("Failed to encode response body: {}", err), 500)
            }
            Error::HashOptions(err) => {
                Response::error(format!("Invalid hash options: {}", err), 400)
            }
            Error::Hash(err) => Response::error(format!("Failed to hash password: {}", err), 500),
            Error::InvalidPasswordHash(err) => {
                Response::error(format!("Invalid password hash: {}", err), 400)
            }
            Error::Verify(err) => {
                Response::error(format!("Failed to verify password: {}", err), 500)
            }
        }
    }
}
