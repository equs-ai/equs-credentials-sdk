use crate::vc::core::PresentationInput;
use oid4vp::presentation_exchange::{ConstraintsField, InputDescriptor, PresentationDefinition};
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

        let claims: Vec<(String, Value)> = fields.iter().map(|field| {
            //TODO: Implement parsing nested fields like $.address.street
            let paths = top_level_paths(field);

            // Supported only filter.const for now
            let value = filter_const(field);

            paths.iter()
                .map(|s| s.to_string())
                .zip(std::iter::repeat(value))
                .collect::<Vec<_>>()

        }).flatten().collect();

        let claims = Map::from_iter(claims.into_iter());

        let format = self.format.clone()
            .ok_or(Error::VpFormatParse)?
            .as_object()
            .and_then(|v| v.keys().find(|s| !s.is_empty()))
            .ok_or(Error::VpFormatParse)?
            .to_owned();

        let type_ = match format.as_str() {
            "vc+sd-jwt" => {
                claims.get("vct")
                    .and_then(|v| v.as_str())
                    .ok_or(Error::VpFormatParse)
            },
            _ => Err(Error::VpFormatParse),
        }?;

        let id = self.id.clone();
        Ok(PresentationInput { id, format, type_: type_.to_string(), claims })
    }
}

fn filter_const(field: &ConstraintsField) -> Value {
    let filter = field.clone().filter.unwrap_or(Value::Null);

    filter.as_object()
        .and_then(|obj| obj.get("const"))
        .unwrap_or(&Value::Null)
        .to_owned()
}

fn top_level_paths(field: &ConstraintsField) -> Vec<String> {
    let paths = field.path.iter();

    paths.map(|path| {
        let parts: Vec<&str> = path.split(".").collect();
        let top_level = parts.get(1).unwrap_or(&"");
        top_level.to_string()
    }).filter(|s| !s.is_empty()).collect()
}