use std::fmt;

pub mod vci;
pub mod vp;
pub mod vci_issuer;

#[derive(fmt::Debug)]
pub enum Error {}

// common oauth2/openid
pub type AuthorizationCode = oauth2::AuthorizationCode;
pub type AccessToken = oauth2::AccessToken;


