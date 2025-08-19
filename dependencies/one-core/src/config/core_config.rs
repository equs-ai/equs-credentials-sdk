use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, EnumString};

#[derive(
    Debug,
    Copy,
    Clone,
    Display,
    EnumString,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    AsRefStr,
)]
pub enum KeyAlgorithmType {
    #[serde(rename = "EDDSA")]
    #[strum(serialize = "EDDSA")]
    Eddsa,
    #[serde(rename = "ECDSA")]
    #[strum(serialize = "ECDSA")]
    Ecdsa,
}
