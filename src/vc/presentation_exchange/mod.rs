use crate::utils::json::find_json_element;
use crate::vc::core::PresentationInput;
use crate::vc::{formats, Presentation};
use common_macros::DebugError;
use oid4vp::core::input_descriptor::JsonPath;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use snafu::{ensure, Location, ResultExt, Snafu};
use std::fmt::Debug;
use tracing::{instrument, Level};
use uuid::Uuid;

pub type Constraints = oid4vp::core::input_descriptor::Constraints;
pub type ConstraintsField = oid4vp::core::input_descriptor::ConstraintsField;
pub type ClaimFormatMap = oid4vp::core::input_descriptor::ClaimFormatMap;
pub type ClaimFormat = oid4vp::core::input_descriptor::ClaimFormat;
pub type ClaimFormatDesignation = oid4vp::core::credential_format::ClaimFormatDesignation;
pub type ClaimFormatPayload = oid4vp::core::credential_format::ClaimFormatPayload;
pub type DescriptorMap = oid4vp::core::presentation_submission::DescriptorMap;
pub type InputDescriptor = oid4vp::core::input_descriptor::InputDescriptor;
pub type PresentationSubmission = oid4vp::core::presentation_submission::PresentationSubmission;
pub type PresentationDefinition = oid4vp::core::presentation_definition::PresentationDefinition;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FieldFilter {
    #[serde(rename = "type")]
    type_: String,
    #[serde(rename = "const")]
    const_: Option<String>,
    contains: Option<Contains>,
    items: Option<Items>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Items {
    #[serde(rename = "enum")]
    enum_: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Contains {
    #[serde(rename = "const")]
    const_: String,
}

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("Parse error: {details}"))]
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
    VCFormats {
        #[snafu(implicit)]
        location: Location,
        source: formats::Error,
    },
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RequestedPresentation {
    pub id: String,
    pub presentation: Presentation,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PresentationResponse {
    pub presentations: Json,
    pub presentation_submission: PresentationSubmission,
}

#[instrument(level = Level::TRACE, err(), ret())]
pub(crate) fn prepare_presentation_response(
    requested_presentations: &[RequestedPresentation],
    presentation_definition: &PresentationDefinition,
) -> Result<PresentationResponse> {
    let mut presentation_submission = PresentationSubmission::new(
        Uuid::new_v4(),
        presentation_definition.id().to_owned(),
        vec![],
    );

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

pub(crate) fn validate_against_presentation_definition(
    presentation: &Json,
    presentation_definition: &PresentationDefinition,
    presentation_submission: &PresentationSubmission,
) -> Result<()> {
    presentation_definition
        .validate_presentation(presentation, presentation_submission.descriptor_map())
        .context(VPSnafu)
}

#[instrument(level = Level::TRACE, err(), ret())]
pub fn resolve_presentation_response(
    presentation_response: &PresentationResponse,
    presentation_definition: &PresentationDefinition,
) -> Result<Vec<RequestedPresentation>> {
    let mut result: Vec<RequestedPresentation> = vec![];

    for input_descriptor in presentation_definition.input_descriptors() {
        let descriptor_map = presentation_response
            .presentation_submission
            .descriptor_map()
            .iter()
            .find(|item| item.id() == input_descriptor.id())
            .ok_or(
                ParseSnafu {
                    details: format!(
                        "Requested presentation {} not found in the presentation submission",
                        input_descriptor.id()
                    ),
                }
                .build(),
            )?;

        let presentation_json =
            find_json_element(&presentation_response.presentations, descriptor_map.path()).ok_or(
                ParseSnafu {
                    details: format!(
                        "Requested presentation {:?} not found by path {:?}",
                        input_descriptor.id(),
                        descriptor_map.path()
                    ),
                }
                .build(),
            )?;

        let presentation = match descriptor_map.format() {
            ClaimFormatDesignation::SdJwtVc => {
                let sd_jwt = presentation_json.as_str().ok_or(
                    ParseSnafu {
                        details: "Incorrect presentation format: expected JWT string".to_string(),
                    }
                    .build(),
                )?;

                Presentation::SdJwtVp(sd_jwt.to_string())
            }
            ClaimFormatDesignation::LdpVc => {
                let presentation: ssi::vc::Presentation =
                    serde_json::from_value(presentation_json.clone()).map_err(|err| {
                        ParseSnafu {
                            details: format!("Incorrect presentation format: {err}"),
                        }
                        .build()
                    })?;

                Presentation::LdpVp(presentation)
            }
            _ => FormatNotSupportedSnafu {
                format: descriptor_map.format().to_owned(),
            }
            .fail()?,
        };

        result.push(RequestedPresentation {
            id: input_descriptor.id().to_owned(),
            presentation,
        })
    }

    Ok(result)
}

#[instrument(level = Level::TRACE, err(), ret())]
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

#[instrument(level = Level::TRACE, err(), ret())]
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
#[instrument(level = Level::TRACE, err(), ret())]
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

    submission.descriptor_map_mut().push(DescriptorMap::new(
        input_descriptor.id().to_owned(),
        format,
        path,
    ));

    Ok(())
}

#[instrument(level = Level::TRACE, err(), ret())]
pub fn split_to_inputs(
    presentation_definition: &PresentationDefinition,
) -> Result<Vec<PresentationInput>> {
    let mut inputs: Vec<PresentationInput> = vec![];

    for desc in presentation_definition.input_descriptors().iter() {
        inputs.push(desc.try_into()?)
    }

    Ok(inputs)
}

impl TryInto<PresentationInput> for &InputDescriptor {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn try_into(self) -> Result<PresentationInput> {
        let format = extract_format(self.format())?;

        let type_ = match &format {
            ClaimFormat::SdJwtVc { .. } => parse_sdjwt_vc_type(self)?,
            ClaimFormat::LdpVc { .. } => parse_json_ldp_vc_type(self)?,
            _ => FormatNotSupportedSnafu {
                format: format.name().to_owned(),
            }
            .fail()?,
        };

        Ok(PresentationInput {
            id: self.id().to_string(),
            format: format.to_owned(),
            type_,
            constraints: self.constraints().to_owned(),
        })
    }
}

#[instrument(level = Level::TRACE, err(), ret())]
fn parse_sdjwt_vc_type(input_descriptor: &InputDescriptor) -> Result<String> {
    let constraints_field = find_constraint_field_with_path(input_descriptor, "$.vct")?;
    let filter = parse_filter(constraints_field)?;

    let cred_type = match filter {
        FieldFilter {
            type_: field_type,
            const_: Some(const_val),
            contains: None,
            items: None,
        } => {
            ensure!(
                field_type == "string",
                ParseSnafu {
                    details: "Value of 'filter.type' must be 'string'",
                }
            );

            const_val
        }
        _ => {
            return ParseSnafu {
                details: "Invalid format of the 'filter'",
            }
            .fail()
        }
    };

    Ok(cred_type)
}

#[instrument(level = Level::TRACE, err(), ret())]
fn parse_json_ldp_vc_type(input_descriptor: &InputDescriptor) -> Result<String> {
    let cred_types_filter = find_constraint_field_with_path(input_descriptor, "$.type")?;

    let filter = parse_filter(cred_types_filter)?;

    ensure!(
        filter.type_ == "array",
        ParseSnafu {
            details: "Value of 'filter.type' must be 'array'",
        }
    );

    let cred_type = match filter {
        FieldFilter {
            contains: Some(c),
            items: None,
            const_: None,
            ..
        } => c.const_,
        FieldFilter {
            contains: None,
            items: Some(items),
            const_: None,
            ..
        } => {
            let cred_types: Vec<&String> = items
                .enum_
                .iter()
                .filter(|&s| s != "VerifiableCredential")
                .collect();

            ensure!(
                cred_types.len() == 1,
                ParseSnafu {
                    details: "Must be specified exactly one credential type",
                }
            );

            cred_types[0].clone()
        }
        _ => {
            return ParseSnafu {
                details: "'filter' must specify either 'contains' or 'items'",
            }
            .fail()
        }
    };

    Ok(cred_type)
}

#[instrument(level = Level::TRACE, err(), ret())]
fn extract_format(format_map: &ClaimFormatMap) -> Result<ClaimFormat> {
    let (format_name, format_payload) = format_map
        .iter()
        .next() //FIXME: Seems, it should be one format for specific Input Descriptor?
        .ok_or_else(|| {
            ParseSnafu {
                details: "format is not defined",
            }
            .build()
        })?;

    let json = json!({ String::from(format_name.to_owned()): format_payload });

    serde_json::from_value::<ClaimFormat>(json).map_err(|e| {
        ParseSnafu {
            details: format!("could not parse claim format: {e}"),
        }
        .build()
    })
}

#[instrument(level = Level::TRACE, err(), ret())]
fn find_constraint_field_with_path<'a>(
    descriptor: &'a InputDescriptor,
    path: &str,
) -> Result<&'a ConstraintsField> {
    descriptor
        .constraints()
        .fields()
        .iter()
        .find(|&f| {
            f.filter().is_some_and(|f| !f.is_null()) && f.path().contains(&JsonPath::from(path))
        })
        .ok_or_else(|| {
            ParseSnafu {
                details: format!("'{path}' must be specified as a field constraint"),
            }
            .build()
        })
}

#[instrument(level = Level::TRACE, err(), ret())]
fn parse_filter(constraints: &ConstraintsField) -> Result<FieldFilter> {
    let filter = constraints.filter().ok_or_else(|| {
        ParseSnafu {
            details: "'filter' must be specified in a field constraint",
        }
        .build()
    })?;

    serde_json::from_value(filter.clone()).map_err(|err| {
        ParseSnafu {
            details: format!("could not parse 'filter': {err}"),
        }
        .build()
    })
}

#[instrument(level = Level::TRACE, err(), ret())]
fn extract_input_descriptor<'a>(
    input_descriptor_id: &str,
    presentation_definition: &'a PresentationDefinition,
) -> Result<&'a InputDescriptor> {
    presentation_definition
        .input_descriptors()
        .iter()
        .find(|input_descriptor| input_descriptor.id() == input_descriptor_id)
        .ok_or_else(|| {
            ParseSnafu {
                details: format!("Input descriptor with id {input_descriptor_id} not found"),
            }
            .build()
        })
}

#[instrument(level = Level::TRACE, err(), ret())]
fn extract_vp_format(input_descriptor: &InputDescriptor) -> Result<ClaimFormatDesignation> {
    input_descriptor
        .format()
        .keys()
        .next()
        .map(|s| s.to_owned())
        .ok_or_else(|| {
            ParseSnafu {
                details: "VP format is not found in the input descriptor",
            }
            .build()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oid4vp::core::{
        credential_format::ClaimFormatDesignation,
        input_descriptor::{ConstraintsField, InputDescriptor},
    };
    use rstest::rstest;
    use serde_json::{json, Value};

    #[tokio::test]
    async fn prepare_presentation_response_succeeds_handling_single_case() {
        let requested_presentation = create_requested_presentation_sdjwtvp(
            "descriptor_id",
            sample_sdjwt_presentation().as_str().unwrap(),
        );
        let presentation_definition = create_single_presentation_definition();

        let result =
            prepare_presentation_response(&[requested_presentation], &presentation_definition)
                .unwrap();

        let presentation_submission_id = result.presentation_submission.id().to_owned();

        assert_eq!(
            result,
            PresentationResponse {
                presentations: sample_sdjwt_presentation(),
                presentation_submission: PresentationSubmission::new(
                    presentation_submission_id,
                    "presentation_definition_id".to_string(),
                    vec![DescriptorMap::new(
                        "descriptor_id".to_string(),
                        ClaimFormatDesignation::SdJwtVc,
                        "$".to_string()
                    )]
                ),
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

    #[rstest]
    #[case::sdjwt(sample_sdjwt_presentation(), ClaimFormatDesignation::SdJwtVc)]
    #[case::ldpvc(sample_ldp_presentation(), ClaimFormatDesignation::LdpVc)]
    #[tokio::test]
    async fn resolve_presentation_response_succeeds_on_correct_data(
        #[case] presentation_value: Value,
        #[case] format: ClaimFormatDesignation,
    ) {
        let presentation_response = PresentationResponse {
            presentations: presentation_value.clone(),
            presentation_submission: create_presentation_submission_with_descriptor_format(
                format.clone(),
            ),
        };
        let presentation_definition = create_single_presentation_definition();

        let result =
            resolve_presentation_response(&presentation_response, &presentation_definition)
                .unwrap();

        let presentation = match format {
            ClaimFormatDesignation::SdJwtVc => {
                Presentation::SdJwtVp(presentation_value.as_str().unwrap().to_string())
            }
            ClaimFormatDesignation::LdpVc => {
                Presentation::LdpVp(serde_json::from_value(presentation_value).unwrap())
            }
            _ => panic!("unsupported format"),
        };

        assert_eq!(
            result,
            vec![RequestedPresentation {
                id: "descriptor_id".to_string(),
                presentation,
            },]
        )
    }

    #[tokio::test]
    async fn split_to_inputs_returns_correct_presentation_inputs_for_sdjwt() {
        let presentation_definition = create_single_presentation_definition();

        let result = split_to_inputs(&presentation_definition).unwrap();

        assert_eq!(
            result,
            [PresentationInput {
                id: "descriptor_id".to_string(),
                format: ClaimFormat::SdJwtVc {
                    jwt_alg_values: vec!["ES256".to_string(), "EdDSA".to_string()],
                    kb_alg_values: vec!["ES256".to_string(), "EdDSA".to_string()]
                },
                type_: "https://credentials.example.com/identity_credential".to_string(),
                constraints: presentation_definition.input_descriptors()[0]
                    .constraints()
                    .clone(),
            }]
        )
    }

    #[rstest]
    #[case::with_contains(sample_ldp_presentation_descriptor_with_contains())]
    #[case::with_enum(sample_ldp_presentation_descriptor_with_enum())]
    #[tokio::test]
    async fn split_to_inputs_returns_correct_presentation_inputs_for_ldpvc(
        #[case] descriptor: InputDescriptor,
    ) {
        let presentation_definition =
            PresentationDefinition::new("presentation_definition_id".to_string(), descriptor);

        let result = split_to_inputs(&presentation_definition).unwrap();

        assert_eq!(
            result,
            [PresentationInput {
                id: "resident-card".to_string(),
                format: ClaimFormat::LdpVc {
                    proof_type: vec![
                        "Ed25519Signature2018".to_string(),
                        "EcdsaSecp256k1Signature2019".to_string(),
                    ]
                },
                type_: "PermanentResidentCard".to_string(),
                constraints: presentation_definition.input_descriptors()[0]
                    .constraints()
                    .clone(),
            }]
        )
    }

    #[rstest]
    #[case::invlaid_type(
        sample_ldp_presentation_descriptor_invalid_type(),
        "Value of 'filter.type' must be 'array'"
    )]
    #[case::contains_and_items(
        sample_ldp_presentation_descriptor_both_items_and_contains(),
        "'filter' must specify either 'contains' or 'items'"
    )]
    #[case::neither_items_nor_contains(
        sample_ldp_presentation_descriptor_neither_items_nor_contains(),
        "'filter' must specify either 'contains' or 'items'"
    )]
    #[case::without_filter(
        sample_ldp_presentation_descriptor_without_filter(),
        "'$.type' must be specified as a field constraint"
    )]
    #[tokio::test]
    async fn split_to_inputs_for_ldpvc_fails_when_descriptor_is_not_valid(
        #[case] descriptor: InputDescriptor,
        #[case] err_message: &str,
    ) {
        let presentation_definition =
            PresentationDefinition::new("presentation_definition_id".to_string(), descriptor);

        let result = split_to_inputs(&presentation_definition);

        assert!(matches!(
            result.err().unwrap(),
            Error::Parse { details, .. } if details == err_message,
        ));
    }

    #[tokio::test]
    #[should_panic(
        expected = "Requested presentation descriptor_id not found in the presentation submission"
    )]
    async fn resolve_presentation_response_fails_on_wrong_descriptor_map_id() {
        let presentation_response = PresentationResponse {
            presentations: sample_sdjwt_presentation(),
            presentation_submission: {
                let descriptor_map = vec![create_descriptor_map(
                    "fake_descriptor_id",
                    ClaimFormatDesignation::SdJwtVc,
                    "$",
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
    #[should_panic(
        expected = "Requested presentation \"descriptor_id\" not found by path \"$.incorrect_presentation_key\""
    )]
    async fn resolve_presentation_response_fails_on_wrong_path() {
        let presentation_response = PresentationResponse {
            presentations: sample_sdjwt_presentation(),
            presentation_submission: {
                let descriptor_map = vec![create_descriptor_map(
                    "descriptor_id",
                    ClaimFormatDesignation::SdJwtVc,
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
                ClaimFormatDesignation::SdJwtVc,
            ),
        };
        let presentation_definition = create_single_presentation_definition();

        let result =
            resolve_presentation_response(&presentation_response, &presentation_definition)
                .unwrap();
    }

    #[rstest]
    #[case(ClaimFormatDesignation::JwtVcJson)]
    #[case(ClaimFormatDesignation::JwtVc)]
    #[case(ClaimFormatDesignation::MsoMDoc)]
    #[case(ClaimFormatDesignation::Other("fake_string".to_owned()))]
    #[tokio::test]
    #[should_panic(expected = "Unsupported format: ")]
    async fn resolve_presentation_response_fails_on_wrong_format(
        #[case] format: ClaimFormatDesignation,
    ) {
        let presentation_response = PresentationResponse {
            presentations: sample_sdjwt_presentation(),
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
        PresentationDefinition::new("presentation_definition_id".to_string(), input_descriptor)
    }

    fn create_multiple_presentation_definition() -> PresentationDefinition {
        let constraints = sample_input_descriptor_constraints();
        let format = sample_input_descriptor_format_sdjwtvc();

        PresentationDefinition::new(
            "presentation_definition_id".to_string(),
            create_input_descriptor("descriptor_id_1", constraints.clone(), format.clone()),
        )
        .add_input_descriptors(create_input_descriptor(
            "descriptor_id_2",
            constraints.clone(),
            format.clone(),
        ))
        .add_input_descriptors(create_input_descriptor(
            "descriptor_id_3",
            constraints.clone(),
            format.clone(),
        ))
    }

    fn create_input_descriptor(
        id: &str,
        constraints: Constraints,
        format: ClaimFormatMap,
    ) -> InputDescriptor {
        InputDescriptor::new(id.to_string(), constraints).set_format(format)
    }

    fn sample_input_descriptor_constraints() -> Constraints {
        let filter = serde_json::from_value(json!(
            {
                "type": "string",
                "const": "https://credentials.example.com/identity_credential",
            }
        ))
        .unwrap();
        Constraints::new().add_constraint(create_constraints_field("$.vct", filter))
    }

    fn sample_input_descriptor_format_sdjwtvc() -> ClaimFormatMap {
        serde_json::from_value(json!({
            "vc+sd-jwt": {
              "sd-jwt_alg_values": ["ES256", "EdDSA"],
              "kb-jwt_alg_values": ["ES256", "EdDSA"]
            }
        }))
        .unwrap()
    }

    fn create_constraints_field(path: &str, filter: Value) -> ConstraintsField {
        ConstraintsField::new(path.to_string()).set_filter(filter)
    }

    fn create_presentation_submission_with_descriptor_format(
        format: ClaimFormatDesignation,
    ) -> PresentationSubmission {
        let descriptor_map = vec![create_descriptor_map("descriptor_id", format, "$")];
        create_presentation_submission(descriptor_map)
    }

    fn create_presentation_submission(
        descriptor_map: Vec<DescriptorMap>,
    ) -> PresentationSubmission {
        PresentationSubmission::new(
            Default::default(),
            "presentation_definition_id".to_string(),
            descriptor_map,
        )
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

    fn create_descriptor_map(
        id: &str,
        format: ClaimFormatDesignation,
        path: &str,
    ) -> DescriptorMap {
        DescriptorMap::new(id.to_string(), format, path.to_string())
    }

    fn sample_sdjwt_presentation() -> Value {
        json!(
            "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6bG9jYWxob3N0JTNBODA4OCNrZXktMCJ9.eyJfc2QiOlsiWGo2b2gtb2Q3ZWxSYWJsWEY0bWtBV25DUERVTFlMTXdoYWNrZ1hrUW9ERSIsImF0WXFsdlNTUUpKcy1CT0M1bnNHdk1sT2pka2VINkV5X1M4WGhIcVVNZkUiXSwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsXzIiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlZTY1OWJ5WHU0cnFjdWpqclJMRmk1N005V2ZGOHVBMnVaZkJ3UjdlSGlDRnYiLCJuYmYiOjE3MjkxNzkxMTcsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOndlYjpsb2NhbGhvc3QlM0E4MDg4IiwiaWF0IjoxNzI5MTc5MTE3LCJleHAiOjE3NjA3MTUxMTcsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJ5dXJteEE0VXBVZVZ2a3oxb0huUktpd2E2U19OVi1DWlpSQnBLakFkU1BVIiwieSI6Imxwb0NQQTUxcXVKTEU0S0xvajVEQTlMcU1sOE1ZUTRTbjdWUkVmeFpJVG8ifX19.bzL9_sEGMw_4LFZ8_NI1-pmgrTZ18rU4QjZR4jrQ8ZFlLplE2Ekgukgpk4sTamSZkHn8Dx1UI1fxFB2qphaSmw~WyI3LXlZS2M3R21yRS1faV9namZJNUFBIiwgImVtYWlsIiwgIkhBUkRDT0RFREBnbWFpbC5jb20iXQ~WyJ6MGJpN0xiRTFPRkdRZmxZMjE2VUxBIiwgInVzZXJuYW1lIiwgIlVTRVIiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJub25jZSI6InJ3RDFFWmwybGJiT1BJQkZXeEtpNlVpUkhGUVhxdXBPdXlwajZJdkRsX0kiLCJhdWQiOiJkaWQ6a2V5OnpEbmFleWhQTFhGc1VFRktqbTY0ZUUzdzRSOU1XTHFRQmNYRDJOdWRMZjZmWk1EdlEiLCJpYXQiOjE3MjkxNzkxMjMsInNkX2hhc2giOiJ5VDRTNnk1S1F4Q0tkQkc0bzZDaUE0YmxjS0t0Y1Z0Sk1IUWMzaEJTcHY4In0.OLRtLvwoiZ7UeOfMVrh7DzJ2f_MiZhEIcANmrHOARRRqoUos5y85GWHRv9JsPzgSZ8wd5Uwso75ZlydgiTGKxA"
        )
    }

    fn sample_ldp_presentation_descriptor_with_enum() -> InputDescriptor {
        serde_json::from_value(json!(
            {
                "id": "resident-card",
                "name": "Identity VC",
                "purpose": "We want a resident card",
                "format": {
                    "ldp_vc": {
                       "proof_type": [
                        "Ed25519Signature2018",
                        "EcdsaSecp256k1Signature2019"
                       ]
                    }
                },
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.type"],
                            "filter": {
                                "type": "array",
                                "items": {
                                    "enum": ["VerifiableCredential", "PermanentResidentCard"]
                                }
                            }
                        }
                    ]
                }
            }

        ))
        .unwrap()
    }

    fn sample_ldp_presentation_descriptor_with_contains() -> InputDescriptor {
        serde_json::from_value(json!(
            {
                "id": "resident-card",
                "name": "Identity VC",
                "purpose": "We want a resident card",
                "format": {
                    "ldp_vc": {
                       "proof_type": [
                        "Ed25519Signature2018",
                        "EcdsaSecp256k1Signature2019"
                       ]
                    }
                },
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.type"],
                            "filter": {
                                "type": "array",
                                "contains": {
                                    "const": "PermanentResidentCard"
                                }
                            }
                        }
                    ]
                }
            }

        ))
        .unwrap()
    }

    fn sample_ldp_presentation_descriptor_invalid_type() -> InputDescriptor {
        serde_json::from_value(json!(
            {
                "id": "resident-card",
                "name": "Identity VC",
                "purpose": "We want a resident card",
                "format": {
                    "ldp_vc": {
                       "proof_type": [
                        "Ed25519Signature2018",
                        "EcdsaSecp256k1Signature2019"
                       ]
                    }
                },
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.type"],
                            "filter": {
                                "type": "string", // invalid type
                                "contains": {
                                    "const": "PermanentResidentCard"
                                }
                            }
                        }
                    ]
                }
            }

        ))
        .unwrap()
    }

    fn sample_ldp_presentation_descriptor_both_items_and_contains() -> InputDescriptor {
        serde_json::from_value(json!(
            {
                "id": "resident-card",
                "name": "Identity VC",
                "purpose": "We want a resident card",
                "format": {
                    "ldp_vc": {
                       "proof_type": [
                        "Ed25519Signature2018",
                        "EcdsaSecp256k1Signature2019"
                       ]
                    }
                },
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.type"],
                            "filter": {
                                "type": "array",
                                "contains": {
                                    "const": "PermanentResidentCard"
                                },
                                "items": { // error: specified both: 'contains' and 'items'
                                    "enum": ["VerifiableCredential", "PermanentResidentCard"]
                                }
                            }
                        }
                    ]
                }
            }

        ))
        .unwrap()
    }

    fn sample_ldp_presentation_descriptor_neither_items_nor_contains() -> InputDescriptor {
        serde_json::from_value(json!(
            {
                "id": "resident-card",
                "name": "Identity VC",
                "purpose": "We want a resident card",
                "format": {
                    "ldp_vc": {
                       "proof_type": [
                        "Ed25519Signature2018",
                        "EcdsaSecp256k1Signature2019"
                       ]
                    }
                },
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.type"],
                            "filter": { // error: filter doesn't specify contains/items
                                "type": "array",
                            }
                        }
                    ]
                }
            }

        ))
        .unwrap()
    }

    fn sample_ldp_presentation_descriptor_without_filter() -> InputDescriptor {
        serde_json::from_value(json!(
            {
                "id": "resident-card",
                "name": "Identity VC",
                "purpose": "We want a resident card",
                "format": {
                    "ldp_vc": {
                       "proof_type": [
                        "Ed25519Signature2018",
                        "EcdsaSecp256k1Signature2019"
                       ]
                    }
                },
                "constraints": {
                    "fields": [ // error: 'filter' is not specified
                        {
                            "path": ["$.type"],
                        }
                    ]
                }
            }

        ))
        .unwrap()
    }

    fn sample_ldp_presentation() -> Value {
        json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiablePresentation",
            "verifiableCredential": {
              "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/citizenship/v1"
              ],
              "type": [
                "VerifiableCredential",
                "PermanentResidentCard"
              ],
              "credentialSubject": {
                "id": "did:key:zDnaed83nMWoHJW6gMLzPy4yMkLzqhSHkjtM3SSh7WRFXLgW6",
                "givenName": "John",
                "type": [
                  "PermanentResident",
                  "Person"
                ],
                "birthDate": "09/09/1989",
                "familyName": "Doe"
              },
              "issuer": "did:web:localhost%3A8088",
              "issuanceDate": "2024-10-29T18:11:32.699194+05:00",
              "proof": {
                "type": "EcdsaSecp256r1Signature2019",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:web:localhost%3A8088#key-0",
                "created": "2024-10-29T13:11:32.699344Z",
                "jws": "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..8wvxFlZoq-XbkNasM9pABuIVZb9Cap0SbyF10_2QKdsR47vLqK8VlfIVXA8Se5bm_VsIOrarXk5gZ-irn5nTiw"
              },
              "expirationDate": "2029-10-28T18:11:32.699194+05:00"
            },
            "proof": {
              "type": "EcdsaSecp256r1Signature2019",
              "proofPurpose": "assertionMethod",
              "verificationMethod": "did:key:zDnaed83nMWoHJW6gMLzPy4yMkLzqhSHkjtM3SSh7WRFXLgW6#zDnaed83nMWoHJW6gMLzPy4yMkLzqhSHkjtM3SSh7WRFXLgW6",
              "created": "2024-10-29T13:11:50.810659Z",
              "jws": "eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..yoLIxlzoxA63refRlh_ZHsF5yMleTZQfK_xs3FMOMxVIxyW7wgS3RaR8w_3F1LxxnavylMeL-ixgqqBqq5WUvg"
            },
            "holder": "did:key:zDnaed83nMWoHJW6gMLzPy4yMkLzqhSHkjtM3SSh7WRFXLgW6"
          }
        )
    }
}
