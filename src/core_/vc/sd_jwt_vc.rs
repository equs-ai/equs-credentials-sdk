use serde_json::Map;

use crate::core_::vc;

pub const SD_JWT_VC: &str = "vc+sd-jwt";

// Basic types definitions
pub type Claims = Map<String, serde_json::Value>;
pub type Credential = vc::JWTRaw;
pub type Presentation = vc::JWTRaw;
pub type Disclosure = String;

// Metadata
pub struct VCMetadata {
    pub disclosures: Vec<Disclosure>,
}
pub struct VPMetadata {
    pub disclosures: Vec<Disclosure>,
}

impl vc::HasClaims<Claims> for Credential {
    fn parse_claims(&self) -> Claims {
        todo!()
    }
}

impl vc::HasCredential<Credential> for Presentation {
    fn get_credential(&self) -> Credential {
        todo!()
    }
}

pub trait SdJwtAPI: vc::API<Claims, Credential, Presentation, VCMetadata, VPMetadata> {}