use oid4vp::presentation_exchange::{ConstraintsField, InputDescriptor, PresentationDefinition};
use serde_json::{Map, Value};
use snafu::Snafu;
use std::fmt::Debug;
use tracing::{instrument, Level};

use crate::vc::core::PresentationInput;

#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Could not parse vp-format from presentation definition"))]
    VpFormatParse,
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        let mut error: &dyn std::error::Error = self;
        while let Some(source) = error.source() {
            write!(fmt, "\n Cause: {}", source)?;
            error = source;
        }

        Ok(())
    }
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
pub fn split_to_inputs(
    presentation_definition: &PresentationDefinition,
) -> Result<Vec<PresentationInput>, Error> {
    let mut inputs: Vec<PresentationInput> = vec![];

    for desc in presentation_definition.input_descriptors.iter() {
        inputs.push(desc.try_into()?)
    }

    Ok(inputs)
}

impl TryInto<PresentationInput> for &InputDescriptor {
    type Error = Error;

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    fn try_into(self) -> Result<PresentationInput, Self::Error> {
        let fields = self.constraints.fields.clone().unwrap_or_default();
        let paths: Vec<&String> = fields.iter().flat_map(|f| f.path.iter()).collect();

        let claims: Vec<(String, Value)> = fields
            .iter()
            .flat_map(|field| {
                //TODO: Implement parsing nested fields like $.address.street
                let paths = top_level_paths(field);

                // Supported only filter.const for now
                let value = filter_const(field);

                paths
                    .iter()
                    .map(|s| s.to_string())
                    .zip(std::iter::repeat(value))
                    .collect::<Vec<_>>()
            })
            .collect();

        let claims = Map::from_iter(claims);

        let format = self
            .format
            .clone()
            .ok_or(VpFormatParseSnafu.build())?
            .as_object()
            .and_then(|v| v.keys().find(|s| !s.is_empty()))
            .ok_or(Error::VpFormatParse)?
            .to_owned();

        let type_ = match format.as_str() {
            "vc+sd-jwt" => claims
                .get("vct")
                .and_then(|v| v.as_str())
                .ok_or(Error::VpFormatParse),
            _ => VpFormatParseSnafu.fail(),
        }?;

        let id = self.id.clone();
        Ok(PresentationInput {
            id,
            format,
            type_: type_.to_string(),
            claims,
        })
    }
}

#[instrument(
    level = Level::TRACE
)]
fn filter_const(field: &ConstraintsField) -> Value {
    let filter = field.clone().filter.unwrap_or(Value::Null);

    filter
        .as_object()
        .and_then(|obj| obj.get("const"))
        .unwrap_or(&Value::Null)
        .to_owned()
}

#[instrument(
    level = Level::TRACE,
    ret(level = Level::TRACE)
)]
fn top_level_paths(field: &ConstraintsField) -> Vec<String> {
    let paths = field.path.iter();

    paths
        .map(|path| {
            let parts: Vec<&str> = path.split('.').collect();
            let top_level = parts.get(1).unwrap_or(&"");
            top_level.to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}
