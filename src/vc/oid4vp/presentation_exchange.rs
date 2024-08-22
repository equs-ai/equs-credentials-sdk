use crate::vc::core::PresentationInput;
use oid4vp::presentation_exchange::{InputDescriptor, PresentationDefinition};
use serde_json::{Map, Value};


#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("could not parse vp-format from presentation definition")]
    VpFormatParse,
}

pub fn split_to_inputs(presentation_definition: &PresentationDefinition) -> Result<Vec<PresentationInput>, Error> {
    let mut inputs: Vec<PresentationInput> = vec![];

    for desc in presentation_definition.input_descriptors.iter() {
        inputs.push(desc.try_into()?)
    }

    Ok(inputs)
}

impl TryInto<PresentationInput> for &InputDescriptor {
    type Error = Error;

    fn try_into(self) -> Result<PresentationInput, Self::Error> {
        let fields = self.constraints.fields.clone().unwrap_or(vec![]);
        let paths: Vec<&String> = fields.iter().flat_map(|f| f.path.iter()).collect();

        //TODO: Implement parsing nested fields like $.address.street
        let stripped: Vec<(String, Value)> = paths.iter().map(|p| {
            let paths: Vec<&str> = p.split(".").collect();
            let top_level_claim = paths
                .get(1)
                .unwrap_or(&"");
            (top_level_claim.to_string(), Value::Bool(true))
        }).collect();

        let claims = Map::from_iter(stripped.into_iter());

        let format = self.format.clone()
            .ok_or(Error::VpFormatParse)?
            .as_object()
            .and_then(|v| v.keys().find(|s| !s.is_empty()))
            .ok_or(Error::VpFormatParse)?
            .to_owned();

        let id = self.id.clone();
        Ok(PresentationInput { id, format, claims })
    }
}