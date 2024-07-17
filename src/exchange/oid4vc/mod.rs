use std::fmt;
use oid4vci::core::profiles::CoreProfilesOffer;
use crate::core_::vc;

pub mod vci;
pub mod vp;

#[derive(fmt::Debug)]
pub enum Error {}

// common oauth2/openid
pub type AuthorizationCode = oauth2::AuthorizationCode;
pub type AccessToken = oauth2::AccessToken;


