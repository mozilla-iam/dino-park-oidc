use thiserror::Error;

#[derive(Error, Debug)]
pub enum OidcError {
    #[error("Mismatching issuer.")]
    IssuerMismatch,
    #[error("Invalid token.")]
    ValidationError,
    #[error("Remote keys missing.")]
    NoRemoteKeys,
    #[error("Invalid remote keys.")]
    InvalidRemoteKeys,
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid url: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("jwt error: {0}")]
    JwtError(#[from] biscuit::errors::Error),
    #[error("jwt validation error: {0}")]
    JwtValidation(#[from] biscuit::errors::ValidationError),
    #[error("remote get error: {0}")]
    RemoteGet(#[from] shared_expiry_get::ExpiryGetError),
}
