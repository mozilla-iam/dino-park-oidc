use biscuit::jwk::JWK;
use biscuit::Empty;
use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use failure::Error;
use futures::future::TryFutureExt;
use log::debug;
use log::info;
use reqwest::Client;
use serde_json::Value;
use shared_expiry_get::Expiry;
use shared_expiry_get::ExpiryFut;
use shared_expiry_get::ExpiryGetError;
use shared_expiry_get::Provider;
use url::Url;

pub struct RemoteKeysProvider {
    pub jwk_url: Url,
}

#[derive(Debug, Clone)]
pub struct RemoteKeys {
    pub keys: Vec<JWK<Empty>>,
    pub expiry: DateTime<Utc>,
}

impl RemoteKeysProvider {
    pub fn new(jwk_url_str: &str) -> Result<Self, Error> {
        let jwk_url = jwk_url_str.parse()?;
        Ok(RemoteKeysProvider { jwk_url })
    }
}

impl Provider<RemoteKeys> for RemoteKeysProvider {
    fn update(&self) -> ExpiryFut<RemoteKeys> {
        info!("updating: {}", self.jwk_url);
        let keys = get_keys(self.jwk_url.clone());
        Box::pin(
            keys.map_ok(|jwks| RemoteKeys {
                keys: jwks,
                expiry: Utc::now() + Duration::days(1),
            })
            .map_err(|e| ExpiryGetError::UpdateFailed(e.to_string())),
        )
    }
}
impl Expiry for RemoteKeys {
    fn valid(&self) -> bool {
        debug!("valid?");
        self.expiry > Utc::now()
    }
}

async fn get_keys(url: Url) -> Result<Vec<JWK<Empty>>, Error> {
    let client = Client::new().get(url);
    let res = client.send().map_err(Error::from).await?;
    let mut keys: Value = res.json().map_err(Error::from).await?;
    serde_json::from_value::<Vec<JWK<Empty>>>(keys["keys"].take()).map_err(Into::into)
}
