use crate::error::OidcError;
use crate::keys::RemoteKeys;
use crate::keys::RemoteKeysProvider;
use biscuit::jwa;
use biscuit::jwk::AlgorithmParameters;
use biscuit::jws;
use biscuit::Empty;
use biscuit::ValidationOptions;
use failure::Error;
use futures::future::BoxFuture;
use futures::FutureExt;
use log::debug;
use reqwest::get;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json;
use serde_json::Value;
use shared_expiry_get::RemoteStore;
use url::Url;

#[derive(Clone)]
pub struct Provider {
    pub issuer: String,
    pub auth_url: Url,
    pub token_url: Url,
    pub user_info_url: Url,
    pub raw_configuration: Value,
    pub remote_key_set: RemoteStore<RemoteKeys, RemoteKeysProvider>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProviderJson {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: String,
}

impl Provider {
    pub async fn from_issuer(issuer: &str) -> Result<Self, Error> {
        let well_known =
            Url::parse(issuer).and_then(|u| u.join(".well-known/openid-configuration"))?;
        let res: Value = get(well_known).await?.error_for_status()?.json().await?;

        let p: ProviderJson = serde_json::from_value(res.clone())?;

        if p.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
            return Err(OidcError::IssuerMismatch.into());
        }

        Ok(Provider {
            issuer: p.issuer,
            auth_url: Url::parse(&p.authorization_endpoint)?,
            token_url: Url::parse(&p.token_endpoint)?,
            user_info_url: Url::parse(&p.userinfo_endpoint)?,
            raw_configuration: res,
            remote_key_set: RemoteStore::new(RemoteKeysProvider::new(&p.jwks_uri)?),
        })
    }
}

impl Provider {
    pub fn verify_and_decode(
        &self,
        token: String,
    ) -> BoxFuture<'static, Result<biscuit::ClaimsSet<Value>, Error>> {
        debug!("verify and decode");
        self.remote_key_set
            .get()
            .map(move |res| match res {
                Ok(remote) => {
                    let jwk = remote.keys.get(0).ok_or_else(|| OidcError::NoRemoteKeys)?;
                    let rsa = if let AlgorithmParameters::RSA(x) = &jwk.algorithm {
                        x
                    } else {
                        return Err(OidcError::InvalidRemoteKeys.into());
                    };
                    let c: jws::Compact<biscuit::ClaimsSet<Value>, Empty> =
                        jws::Compact::new_encoded(&token);
                    match c.decode(&rsa.jws_public_key_secret(), jwa::SignatureAlgorithm::RS256) {
                        Ok(c) => Ok(c.unwrap_decoded().1),
                        Err(e) => Err(e.into()),
                    }
                }
                Err(e) => Err(e.into()),
            })
            .boxed()
    }
}
pub fn check(
    item: &biscuit::ClaimsSet<Value>,
    validation_options: ValidationOptions,
) -> Result<(), Error> {
    item.registered
        .validate(validation_options)
        .map_err(Into::into)
}

#[cfg(test)]
mod test {
    use super::*;
    use biscuit::ClaimsSet;
    use biscuit::RegisteredClaims;
    use biscuit::SingleOrMultiple;
    use biscuit::StringOrUri;
    use serde_json::Value;

    #[tokio::test]
    async fn test_from_issuer_mozilla() {
        let p = Provider::from_issuer("https://auth.mozilla.auth0.com/").await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn test_from_issuer_google() {
        let p = Provider::from_issuer("https://accounts.google.com/").await;
        assert!(p.is_ok());
    }
    #[test]
    fn test_validate_empty_sets() {
        let claim_set = ClaimsSet {
            registered: Default::default(),
            private: Value::default(),
        };
        let validation_options = ValidationOptions::default();
        let res = check(&claim_set, validation_options);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_audience() {
        let claim_set = ClaimsSet {
            registered: {
                RegisteredClaims {
                    audience: Some(SingleOrMultiple::Single(StringOrUri::String(
                        "foo".to_string(),
                    ))),
                    ..Default::default()
                }
            },
            private: Value::default(),
        };
        let validation_options = ValidationOptions::default();
        let res = check(&claim_set, validation_options);
        assert!(res.is_ok());
    }
}
