use failure::Fail;

#[derive(Fail, Debug)]
pub enum OidcError {
    #[fail(display = "Mismatching issuer.")]
    IssuerMismatch,
    #[fail(display = "Invalid token.")]
    ValidationError,
    #[fail(display = "Remote keys missing.")]
    NoRemoteKeys,
    #[fail(display = "Invalid remote keys.")]
    InvalidRemoteKeys,
}
