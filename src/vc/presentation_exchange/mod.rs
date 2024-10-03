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

#[derive(Debug, Clone, PartialEq)]
pub struct RequestedPresentation {
    pub id: String,
    pub presentation: Presentation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PresentationResponse {
    pub presentations: Json,
    pub presentation_submission: PresentationSubmission,
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(),
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
    ret(),
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
    ret(),
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
    ret(),
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
    ret(),
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
    ret(),
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
    ret(),
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
    ret(),
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
    ret(),
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
        ret(),
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
    ret(),
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
    ret(),
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
    level = Level::TRACE,
    ret(),
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
    ret(),
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
#[cfg(test)]
mod tests {
    use super::*;
    use oid4vp::presentation_exchange::Constraints;
    use oid4vp::utils::NonEmptyVec;
    use rstest::rstest;
    use serde_json::{json, Value};

    #[tokio::test]
    async fn prepare_presentation_response_succeeds_handling_single_case() {
        let requested_presentation =
            create_requested_presentation_sdjwtvp("descriptor_id", "fake_sd_jwt_vp");
        let presentation_definition = create_single_presentation_definition();

        let result =
            prepare_presentation_response(&[requested_presentation], &presentation_definition)
                .unwrap();

        let presentation_submission_id = result.presentation_submission.id.clone();

        assert_eq!(
            result,
            PresentationResponse {
                presentations: json!("fake_sd_jwt_vp"),
                presentation_submission: PresentationSubmission {
                    id: presentation_submission_id,
                    definition_id: "presentation_definition_id".to_string(),
                    descriptor_map: vec![DescriptorMap {
                        id: "descriptor_id".to_string(),
                        format: "vc+sd-jwt".to_string(),
                        path: "$".to_string()
                    }]
                }
            }
        )
    }

    #[tokio::test]
    async fn prepare_presentation_response_succeeds_handling_multiple_case() {
        let rp_1 = create_requested_presentation_sdjwtvp("descriptor_id_1", "fake_sd_jwt_vp_1");
        let rp_2 = create_requested_presentation_sdjwtvp("descriptor_id_2", "fake_sd_jwt_vp_2");
        let presentation_definition = create_multiple_presentation_definition();

        let result =
            prepare_presentation_response(&[rp_1, rp_2], &presentation_definition).unwrap();
        assert_eq!(
            result.presentations,
            json!([
                "fake_sd_jwt_vp_1".to_string(),
                "fake_sd_jwt_vp_2".to_string()
            ])
        )
    }

    #[tokio::test]
    async fn resolve_presentation_response_succeeds_on_correct_data() {
        let presentation_response = PresentationResponse {
            presentations: json!("fake_presentation"),
            presentation_submission: create_presentation_submission_with_descriptor_format(
                SD_JWT_VC,
            ),
        };
        let presentation_definition = create_single_presentation_definition();

        let result =
            resolve_presentation_response(&presentation_response, &presentation_definition)
                .unwrap();

        assert_eq!(
            result,
            vec![RequestedPresentation {
                id: "descriptor_id".to_string(),
                presentation: Presentation::SdJwtVp("fake_presentation".to_string()),
            },]
        )
    }

    #[tokio::test]
    async fn validate_claims_succeeds_on_correct_data() {
        let claims = json!({
            "vct": "fake_vct_value"
        });
        let presentation_definition = create_single_presentation_definition();
        validate_claims(&claims, "descriptor_id", &presentation_definition).unwrap();
    }

    #[tokio::test]
    async fn split_to_inputs_returns_correct_presentation_inputs() {
        let presentation_definition = create_single_presentation_definition();
        let result = split_to_inputs(&presentation_definition).unwrap();

        let mut claims = serde_json::Map::new();
        claims.insert(
            "vct".to_string(),
            Value::String("value_of_filter.const".to_string()),
        );

        assert_eq!(
            result,
            [PresentationInput {
                id: "descriptor_id".to_string(),
                format: "vc+sd-jwt".to_string(),
                type_: "value_of_filter.const".to_string(),
                claims
            }]
        )
    }

    #[tokio::test]
    #[should_panic(
        expected = "Requested presentation descriptor_id not found in the presentation submission"
    )]
    async fn resolve_presentation_response_fails_on_wrong_descriptor_map_id() {
        let presentation_response = PresentationResponse {
            presentations: Value::String("fake_sd_jwt_vp".to_string()),
            presentation_submission: {
                let descriptor_map =
                    vec![create_descriptor_map("fake_descriptor_id", SD_JWT_VC, "$")];
                create_presentation_submission(descriptor_map)
            },
        };
        let presentation_definition = create_single_presentation_definition();

        let result =
            resolve_presentation_response(&presentation_response, &presentation_definition)
                .unwrap();
    }

    #[tokio::test]
    #[should_panic(
        expected = "Requested presentation \"descriptor_id\" not found by path \"$.incorrect_presentation_key\""
    )]
    async fn resolve_presentation_response_fails_on_wrong_path() {
        let presentation_response = PresentationResponse {
            presentations: json!({"presentation_key": "presentation_value"}),
            presentation_submission: {
                let descriptor_map = vec![create_descriptor_map(
                    "descriptor_id",
                    SD_JWT_VC,
                    "$.incorrect_presentation_key",
                )];
                create_presentation_submission(descriptor_map)
            },
        };
        let presentation_definition = create_single_presentation_definition();

        let result =
            resolve_presentation_response(&presentation_response, &presentation_definition)
                .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Incorrect presentation format: expected JWT string")]
    async fn resolve_presentation_response_fails_on_sdjwtvc_format_but_non_string_presentation() {
        let presentation_response = PresentationResponse {
            presentations: json!(1),
            presentation_submission: create_presentation_submission_with_descriptor_format(
                SD_JWT_VC,
            ),
        };
        let presentation_definition = create_single_presentation_definition();

        let result =
            resolve_presentation_response(&presentation_response, &presentation_definition)
                .unwrap();
    }

    #[rstest]
    #[case(crate::vc::JWT_VC_JSON)]
    #[case(crate::vc::JWT_VC_JSON_LD)]
    #[case(crate::vc::LDP_VC)]
    #[case(crate::vc::MSO_MDOC)]
    #[case("fake_string")]
    #[tokio::test]
    #[should_panic(expected = "Unsupported format: ")]
    async fn resolve_presentation_response_fails_on_wrong_format(#[case] format: &str) {
        let presentation_response = PresentationResponse {
            presentations: json!("fake_presentation"),
            presentation_submission: create_presentation_submission_with_descriptor_format(format),
        };
        let presentation_definition = create_single_presentation_definition();

        let result =
            resolve_presentation_response(&presentation_response, &presentation_definition)
                .unwrap();
    }

    fn create_single_presentation_definition() -> PresentationDefinition {
        let input_descriptor = create_input_descriptor(
            "descriptor_id",
            sample_input_descriptor_constraints(),
            sample_input_descriptor_format_sdjwtvc(),
        );
        PresentationDefinition {
            id: "presentation_definition_id".to_string(),
            input_descriptors: vec![input_descriptor],
            name: None,
            purpose: None,
            format: None,
        }
    }

    fn create_multiple_presentation_definition() -> PresentationDefinition {
        let constraints = sample_input_descriptor_constraints();
        let format = sample_input_descriptor_format_sdjwtvc();

        let input_descriptors = vec![
            create_input_descriptor("descriptor_id_1", constraints.clone(), format.clone()),
            create_input_descriptor("descriptor_id_2", constraints.clone(), format.clone()),
            create_input_descriptor("descriptor_id_3", constraints.clone(), format.clone()),
        ];

        PresentationDefinition {
            id: "presentation_definition_id".to_string(),
            input_descriptors,
            name: None,
            purpose: None,
            format: None,
        }
    }

    fn create_input_descriptor(
        id: &str,
        constraints: Constraints,
        format: Option<Value>,
    ) -> InputDescriptor {
        InputDescriptor {
            id: id.to_string(),
            constraints,
            name: None,
            purpose: None,
            format,
        }
    }

    fn sample_input_descriptor_constraints() -> Constraints {
        let format = Some(
            serde_json::from_value(json!(
                {
                    "const": "value_of_filter.const",
                }
            ))
            .unwrap(),
        );
        Constraints {
            fields: Some(vec![
                create_constraints_field("$.vct", None),
                create_constraints_field("$.vct", format),
            ]),
            limit_disclosure: None,
        }
    }

    fn sample_input_descriptor_format_sdjwtvc() -> Option<Value> {
        Some(
            serde_json::from_value(json!({
               "vc+sd-jwt": {
                   "alg": ["EdDSA", "ES256K"]
               }
            }))
            .unwrap(),
        )
    }

    fn create_constraints_field(path: &str, filter: Option<Value>) -> ConstraintsField {
        ConstraintsField {
            path: NonEmptyVec::new(path.to_string()),
            id: None,
            purpose: None,
            name: None,
            filter,
            optional: None,
            intent_to_retain: None,
        }
    }

    fn create_presentation_submission_with_descriptor_format(
        format: &str,
    ) -> PresentationSubmission {
        let descriptor_map = vec![create_descriptor_map("descriptor_id", format, "$")];
        create_presentation_submission(descriptor_map)
    }

    fn create_presentation_submission(
        descriptor_map: Vec<DescriptorMap>,
    ) -> PresentationSubmission {
        PresentationSubmission {
            id: "".to_string(),
            definition_id: "presentation_definition_id".to_string(),
            descriptor_map,
        }
    }

    fn create_requested_presentation_sdjwtvp(
        id: &str,
        presentation: &str,
    ) -> RequestedPresentation {
        RequestedPresentation {
            id: id.to_string(),
            presentation: Presentation::SdJwtVp(presentation.to_string()),
        }
    }

    fn create_descriptor_map(id: &str, format: &str, path: &str) -> DescriptorMap {
        DescriptorMap {
            id: id.to_string(),
            format: format.to_string(),
            path: path.to_string(),
        }
    }
}
