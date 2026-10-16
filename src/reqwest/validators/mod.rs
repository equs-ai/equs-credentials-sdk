use common_macros::DebugError;
use snafu::Snafu;

pub mod content_size;
pub mod content_type;

pub(super) type Result<T> = std::result::Result<T, HttpPayloadError>;

#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum HttpPayloadError {
    #[snafu(display("Content type validation error: {details}"))]
    ContentType { details: String },
    #[snafu(display("Content size validation error: {details}"))]
    ContentSize { details: String },
}
