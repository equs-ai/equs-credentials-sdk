use agent_sdk::vc::oid4vp::Url;
use uniffi::deps::anyhow;

pub fn parse_url_arg(url: &str) -> anyhow::Result<Url> {
    url.parse().map_err(anyhow::Error::from)
}
