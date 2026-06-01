use crate::common::Error;
use agent_sdk::vc::presentation_exchange::StatusSize;
use agent_sdk::vc::status_formats::StatusListFormat as ASDKStatusListFormat;
use agent_sdk::vc::status_formats::status_list_token_jwt::SLMetadata as ASDKSLMetadata;
use url::Url;

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct SLMetadata {
    pub status_list_url: String,
    pub statuses_nr: u32,
    pub status_size: u8,
}

impl TryFrom<SLMetadata> for ASDKSLMetadata {
    type Error = Error;
    fn try_from(v: SLMetadata) -> Result<Self, Error> {
        Ok(ASDKSLMetadata {
            // `url::Url` has no `TryFrom<String>`; parse explicitly.
            status_list_url: Url::parse(&v.status_list_url)
                .map_err(|e| Error::Core(e.to_string()))?,
            statuses_nr: v.statuses_nr as usize,
            // `StatusSize::try_from`'s error type isn't ours.
            status_size: StatusSize::try_from(v.status_size)
                .map_err(|e| Error::Core(e.to_string()))?,
        })
    }
}

impl TryFrom<ASDKSLMetadata> for SLMetadata {
    type Error = Error;
    fn try_from(v: ASDKSLMetadata) -> Result<Self, Error> {
        Ok(SLMetadata {
            status_list_url: v.status_list_url.to_string(),
            statuses_nr: v.statuses_nr as u32,
            status_size: u8::from(v.status_size),
        })
    }
}

#[non_exhaustive]
#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum StatusListFormat {
    StatusListTokenJwt(SLMetadata),
    StatusListTokenCwt,
}

impl TryFrom<StatusListFormat> for ASDKStatusListFormat {
    type Error = Error;
    fn try_from(v: StatusListFormat) -> Result<Self, Error> {
        Ok(match v {
            StatusListFormat::StatusListTokenJwt(m) => {
                ASDKStatusListFormat::StatusListTokenJwt(m.try_into()?)
            }
            StatusListFormat::StatusListTokenCwt => ASDKStatusListFormat::StatusListTokenCwt,
        })
    }
}

impl TryFrom<ASDKStatusListFormat> for StatusListFormat {
    type Error = Error;
    fn try_from(v: ASDKStatusListFormat) -> Result<Self, Error> {
        Ok(match v {
            ASDKStatusListFormat::StatusListTokenJwt(m) => {
                StatusListFormat::StatusListTokenJwt(m.try_into()?)
            }
            ASDKStatusListFormat::StatusListTokenCwt => StatusListFormat::StatusListTokenCwt,
        })
    }
}
