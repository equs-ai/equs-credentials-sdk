use crate::utils::json::find_json_element;
use crate::vc::core::PresentationInput;
use crate::vc::{Claims, Presentation, SD_JWT_VC};
use oid4vp::core::metadata::parameters::verifier::VpFormats;
use oid4vp::presentation_exchange::{
    ConstraintsField, DescriptorMap, InputDescriptor, PresentationDefinition,
    PresentationSubmission,
};
use serde_json::Value as Json;
use snafu::{ensure, Location, ResultExt, Snafu};
use std::fmt::Debug;
use tracing::{instrument, Level};
use uuid::Uuid;

pub mod builder;

#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("Parse error at {location}\n Cause: {details}"))]
    Parse {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    VP {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
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

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct RequestedPresentation {
    pub id: String,
    pub presentation: Presentation,
}

#[derive(Debug, Clone)]
pub struct PresentationResponse {
    pub presentations: Json,
    pub presentation_submission: PresentationSubmission,
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
pub fn prepare_presentation_response(
    requested_presentations: &[RequestedPresentation],
    presentation_definition: &PresentationDefinition,
) -> Result<PresentationResponse> {
    let mut presentation_submission = PresentationSubmission {
        id: Uuid::new_v4().to_string(),
        definition_id: presentation_definition.id.clone(),
        descriptor_map: vec![],
    };

    if requested_presentations.len() == 1 {
        handle_single_presentation(
            &requested_presentations[0],
            presentation_definition,
            &mut presentation_submission,
        )
    } else {
        handle_multiple_presentations(
            requested_presentations,
            presentation_definition,
            &mut presentation_submission,
        )
    }
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
pub fn resolve_presentation_response(
    presentation_response: &PresentationResponse,
    presentation_definition: &PresentationDefinition,
) -> Result<Vec<RequestedPresentation>> {
    let mut result: Vec<RequestedPresentation> = vec![];

    for input_descriptor in &presentation_definition.input_descriptors {
        let descriptor_map = presentation_response
            .presentation_submission
            .descriptor_map
            .iter()
            .find(|item| item.id == input_descriptor.id)
            .ok_or(
                ParseSnafu {
                    details: format!(
                        "Requested presentation {} not found in the presentation submission",
                        input_descriptor.id
                    ),
                }
                .build(),
            )?;

        let presentation_json =
            find_json_element(&presentation_response.presentations, &descriptor_map.path).ok_or(
                ParseSnafu {
                    details: format!(
                        "Requested presentation {:?} not found by path {:?}",
                        input_descriptor.id, descriptor_map.path
                    ),
                }
                .build(),
            )?;

        let presentation = match descriptor_map.format.as_str() {
            SD_JWT_VC => {
                let sd_jwt = presentation_json.as_str().ok_or(
                    ParseSnafu {
                        details: "Incorrect presentation format: expected JWT string".to_string(),
                    }
                    .build(),
                )?;

                Presentation::SdJwtVp(sd_jwt.to_string())
            }
            _ => FormatNotSupportedSnafu {
                format: descriptor_map.format.to_owned(),
            }
            .fail()?,
        };

        result.push(RequestedPresentation {
            id: input_descriptor.id.to_owned(),
            presentation,
        })
    }

    Ok(result)
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
pub fn validate_claims(
    claims: &Claims,
    input_descriptor_id: &str,
    presentation_definition: &PresentationDefinition,
) -> Result<()> {
    let input_descriptor = extract_input_descriptor(input_descriptor_id, presentation_definition)?;
    let constraints_fields = input_descriptor.constraints.fields.as_ref();
    if let Some(constraints) = constraints_fields {
        validate_field_constraints(claims, constraints)?;
    }

    Ok(())
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
fn handle_single_presentation(
    requested_presentation: &RequestedPresentation,
    presentation_definition: &PresentationDefinition,
    presentation_submission: &mut PresentationSubmission,
) -> Result<PresentationResponse> {
    process_requested_presentation(
        requested_presentation,
        None,
        presentation_definition,
        presentation_submission,
    )?;

    let presentations =
        serde_json::to_value(&requested_presentation.presentation).map_err(|err| {
            ParseSnafu {
                details: format!("Presentation parse error: {err}"),
            }
            .build()
        })?;

    Ok(PresentationResponse {
        presentations,
        presentation_submission: presentation_submission.clone(),
    })
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
fn handle_multiple_presentations(
    requested_presentations: &[RequestedPresentation],
    presentation_definition: &PresentationDefinition,
    presentation_submission: &mut PresentationSubmission,
) -> Result<PresentationResponse> {
    let mut presentations: Vec<Presentation> = vec![];

    for (index, presentation) in requested_presentations.iter().enumerate() {
        presentations.push(presentation.presentation.clone());

        process_requested_presentation(
            presentation,
            Some(index),
            presentation_definition,
            presentation_submission,
        )?;
    }

    let presentations = serde_json::to_value(&presentations).map_err(|err| {
        ParseSnafu {
            details: format!("Presentation parse error: {err}"),
        }
        .build()
    })?;

    Ok(PresentationResponse {
        presentations,
        presentation_submission: presentation_submission.clone(),
    })
}

// Helper function to handle the common logic for descriptor_map and path building
#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
fn process_requested_presentation(
    requested_presentation: &RequestedPresentation,
    index: Option<usize>,
    presentation_definition: &PresentationDefinition,
    submission: &mut PresentationSubmission,
) -> Result<()> {
    let input_descriptor =
        extract_input_descriptor(&requested_presentation.id, presentation_definition)?;
    let format = extract_vp_format(input_descriptor)?;
    let path = match index {
        Some(i) => format!("$[{i}]"),
        None => "$".to_string(),
    };

    submission.descriptor_map.push(DescriptorMap {
        id: input_descriptor.id.to_owned(),
        format,
        path,
    });

    Ok(())
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
fn validate_field_constraints(claims: &Json, constraints: &[ConstraintsField]) -> Result<()> {
    for constraint in constraints.iter() {
        for path in constraint.path.iter() {
            ensure!(
                find_json_element(claims, path).is_some(),
                ParseSnafu {
                    details: format!("Requested claim not found by path {path}")
                }
            );
        }
    }
    Ok(())
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
pub fn validate_formats(
    supported_formats: VpFormats,
    presentation_definition: &PresentationDefinition,
) -> Result<()> {
    let vp_format_json = match presentation_definition.format.as_ref() {
        Some(format) => format,
        None => return Ok(()), // presentation definition does not contain any format
    };

    let vp_formats: VpFormats = vp_format_json.clone().try_into().context(VPSnafu)?;

    for vp_format in vp_formats.0.keys() {
        ensure!(
            supported_formats.0.contains_key(vp_format),
            FormatNotSupportedSnafu { format: vp_format }
        )
    }

    Ok(())
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
pub fn split_to_inputs(
    presentation_definition: &PresentationDefinition,
) -> Result<Vec<PresentationInput>> {
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
    fn try_into(self) -> Result<PresentationInput> {
        let fields = self.constraints.fields.clone().unwrap_or_default();
        let paths: Vec<&String> = fields.iter().flat_map(|f| f.path.iter()).collect();

        let claims: Vec<(String, Json)> = fields
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

        let claims = serde_json::Map::from_iter(claims);

        let format = extract_vp_format(self)?;

        let type_ = match format.as_str() {
            SD_JWT_VC => claims.get("vct").and_then(|v| v.as_str()).ok_or(
                ParseSnafu {
                    details: "The 'vct' claim is required for the SD-JWT VC",
                }
                .build(),
            ),
            _ => FormatNotSupportedSnafu { format: &format }.fail(),
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
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
fn extract_input_descriptor<'a>(
    input_descriptor_id: &str,
    presentation_definition: &'a PresentationDefinition,
) -> Result<&'a InputDescriptor> {
    presentation_definition
        .input_descriptors
        .iter()
        .find(|input_descriptor| input_descriptor.id == input_descriptor_id)
        .ok_or_else(|| {
            ParseSnafu {
                details: format!("Input descriptor with id {input_descriptor_id} not found"),
            }
            .build()
        })
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
fn extract_vp_format(input_descriptor: &InputDescriptor) -> Result<String> {
    input_descriptor
        .format
        .as_ref()
        .and_then(|v| v.as_object())
        .and_then(|obj| obj.keys().find(|s| !s.is_empty()))
        .map(|key| key.to_string())
        .ok_or_else(|| {
            ParseSnafu {
                details: "VP format is not found in the input descriptor",
            }
            .build()
        })
}

#[instrument(
    level = Level::TRACE
)]
fn filter_const(field: &ConstraintsField) -> Json {
    let filter = field.clone().filter.unwrap_or(Json::Null);

    filter
        .as_object()
        .and_then(|obj| obj.get("const"))
        .unwrap_or(&Json::Null)
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
