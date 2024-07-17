use crate::core_::vc;

pub const LDP_VC: &str = "ldp_vc";
pub const LDP_VP: &str = "ldp_vp";

pub type Claims = ssi::vc::Credential;
pub type Credential = ssi::vc::Credential;
pub type Presentation = ssi::vc::Presentation;
// Metadata
pub struct VCMetadata;
pub struct VPMetadata;

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

pub trait LdpVcAPI: vc::API<Claims, Credential, Presentation, VCMetadata, VPMetadata> {}