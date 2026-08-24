use crate::common::Error;
use equs_sdk::vc::presentation_exchange::StatusSize;
use equs_sdk::vc::status_formats::StatusListFormat as EqusSdkStatusListFormat;
use equs_sdk::vc::status_formats::status_list_token_jwt::SLMetadata as EqusSdkSLMetadata;
use url::Url;

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct SLMetadata {
    pub status_list_url: String,
    pub statuses_nr: u32,
    pub status_size: u8,
}

impl TryFrom<SLMetadata> for EqusSdkSLMetadata {
    type Error = Error;
    fn try_from(v: SLMetadata) -> Result<Self, Error> {
        Ok(EqusSdkSLMetadata {
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

impl TryFrom<EqusSdkSLMetadata> for SLMetadata {
    type Error = Error;
    fn try_from(v: EqusSdkSLMetadata) -> Result<Self, Error> {
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

impl TryFrom<StatusListFormat> for EqusSdkStatusListFormat {
    type Error = Error;
    fn try_from(v: StatusListFormat) -> Result<Self, Error> {
        Ok(match v {
            StatusListFormat::StatusListTokenJwt(m) => {
                EqusSdkStatusListFormat::StatusListTokenJwt(m.try_into()?)
            }
            StatusListFormat::StatusListTokenCwt => EqusSdkStatusListFormat::StatusListTokenCwt,
        })
    }
}

impl TryFrom<EqusSdkStatusListFormat> for StatusListFormat {
    type Error = Error;
    fn try_from(v: EqusSdkStatusListFormat) -> Result<Self, Error> {
        Ok(match v {
            EqusSdkStatusListFormat::StatusListTokenJwt(m) => {
                StatusListFormat::StatusListTokenJwt(m.try_into()?)
            }
            EqusSdkStatusListFormat::StatusListTokenCwt => StatusListFormat::StatusListTokenCwt,
        })
    }
}
