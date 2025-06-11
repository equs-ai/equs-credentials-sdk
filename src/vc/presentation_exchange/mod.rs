//! DIF Presentation Exchange related methods.

use crate::utils::logs::sanitize_log_msg;
use crate::vault::{
    CannotCreateJSONPathSnafu, ClaimsDidNotPassFilteringSnafu, ClaimsParsingSnafu,
    UnsupportedCredentialFormatSnafu,
};
use crate::vc::claims::Claims;
use crate::vc::core::api::PresentationRestrictionValue;
use crate::vc::core::{PresentationInput, PresentationRestriction};
use crate::vc::{
    ClaimFormatDesignation, Credential, HasClaims, HasVCFormat, JsonPath, Presentation,
    RequestedPresentation, formats,
};
use common_macros::DebugError;
use jsonpath_rust::JsonPathValue;
use openid4vp::core::presentation_submission::NoClaimsDecoder;
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, Value, json};
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use tracing::{Level, instrument};
use uuid::Uuid;
// IDE removes Level from imports due to absence of usage. This way it is used now
type Level_ = Level;

pub type Constraints = openid4vp::core::input_descriptor::Constraints;
pub type ConstraintsField = openid4vp::core::input_descriptor::ConstraintsField;
pub type ClaimFormatMap = openid4vp::core::credential_format::ClaimFormatMap;
pub type ClaimFormat = openid4vp::core::credential_format::ClaimFormat;
pub type ClaimFormatPayload = openid4vp::core::credential_format::ClaimFormatPayload;
pub type DescriptorMap = openid4vp::core::presentation_submission::DescriptorMap;
pub type InputDescriptor = openid4vp::core::input_descriptor::InputDescriptor;
pub type PresentationSubmission = openid4vp::core::presentation_submission::PresentationSubmission;
pub type PresentationDefinition = openid4vp::core::presentation_definition::PresentationDefinition;
pub type SubmissionRequirement = openid4vp::core::presentation_definition::SubmissionRequirement;
pub type SubmissionRequirementObject =
    openid4vp::core::presentation_definition::SubmissionRequirementObject;
pub type SubmissionRequirementBase =
    openid4vp::core::presentation_definition::SubmissionRequirementBase;
pub type SubmissionRequirementPick =
    openid4vp::core::presentation_definition::SubmissionRequirementPick;
pub type GroupId = openid4vp::core::input_descriptor::GroupId;
pub type StatusSize = ssi_status::token_status_list::StatusSize;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FieldFilter {
    #[serde(rename = "type")]
    type_: Option<String>,
    #[serde(flatten)]
    properties: Option<FieldFilterProperties>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum FieldFilterProperties {
    #[serde(rename = "const")]
    Const(String),
    #[serde(rename = "pattern")]
    Pattern(String),
    #[serde(rename = "items")]
    Items {
        #[serde(rename = "enum")]
        enum_: Vec<String>,
    },
    #[serde(rename = "contains")]
    Contains {
        #[serde(rename = "const")]
        const_: String,
    },
}

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported {
        format: String,
    },
    #[snafu(display("Parse error: {details}"))]
    Parse {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Claims to exclude are not valid: {details}"))]
    InvalidClaimsToExclude {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    VPValidation {
        #[snafu(implicit)]
        location: Location,
        source: openid4vp::core::presentation_submission::SubmissionError,
    },
    VCFormats {
        #[snafu(implicit)]
        location: Location,
        source: formats::Error,
    },
    SubmissionValidationError {
        #[snafu(implicit)]
        location: Location,
        source: openid4vp::core::presentation_submission::SubmissionValidationError,
    },

    #[snafu(display("Json path creation error"))]
    JsonPathCreation {
        source: serde_json_path::ParseError,
    },
    NotFound,
}

pub type Result<T> = core::result::Result<T, Error>;

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
    let inputs = presentation_submission
        .find_and_validate_inputs(presentation_definition, presentation, &NoClaimsDecoder {})
        .context(VPValidationSnafu)?;
    if let Some(sub_reqs) = presentation_definition.submission_requirements() {
        for sub_req in sub_reqs {
            let _ = sub_req
                .validate(presentation_definition, &inputs)
                .context(SubmissionValidationSnafu);
        }
    }

    Ok(())
}

#[instrument(level = Level::TRACE, err(), ret())]
pub(crate) fn resolve_presentation_response(
    presentation_response: &PresentationResponse,
    presentation_definition: &PresentationDefinition,
) -> Result<Vec<RequestedPresentation>> {
    let mut result: Vec<RequestedPresentation> = vec![];
    for input_descriptor in presentation_definition.input_descriptors() {
        let ps = presentation_response.clone().presentation_submission;
        let descriptor_map = ps
            .descriptor_map()
            .iter()
            .find(|item| item.id == input_descriptor.id);

        let descriptor_map = if let Some(descriptor_map) = descriptor_map {
            descriptor_map
        } else if input_descriptor.groups.is_empty() {
            return ParseSnafu {
                details: format!(
                    "Requested presentation {} not found in the presentation submission",
                    input_descriptor.id
                ),
            }
            .fail();
        } else {
            continue;
        };

        let presentation = match descriptor_map.format {
            ClaimFormatDesignation::SdJwtVc => {
                let prs_json = extract_json_presentation(
                    presentation_response,
                    input_descriptor.clone().id,
                    &descriptor_map.path,
                )?;

                let sd_jwt = prs_json.as_str().ok_or(
                    ParseSnafu {
                        details: "Incorrect presentation format: expected SD-JWT string"
                            .to_string(),
                    }
                    .build(),
                )?;

                Presentation::SdJwtVp(sd_jwt.to_string())
            }
            ClaimFormatDesignation::LdpVc => {
                let presentation_json = if presentation_response.presentations.is_array() {
                    let path = JsonPath::parse(
                        &descriptor_map
                            .path
                            .to_string()
                            .replace(".verifiableCredential", ""),
                    )
                    .map_err(|e| {
                        ParseSnafu {
                            details: "Could not parse json path",
                        }
                        .build()
                    })?;

                    extract_json_presentation(
                        presentation_response,
                        input_descriptor.clone().id,
                        &path,
                    )?
                } else {
                    &presentation_response.presentations
                };

                let presentation =
                    serde_json::from_value(presentation_json.clone()).map_err(|err| {
                        ParseSnafu {
                            details: format!(
                                "Could not deserialize 'ldp_vp' presentation from json: {err}"
                            ),
                        }
                        .build()
                    })?;

                Presentation::LdpVp(presentation)
            }
            _ => FormatNotSupportedSnafu {
                format: String::from(descriptor_map.format.to_owned()),
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

fn extract_json_presentation<'a>(
    presentation_response: &'a PresentationResponse,
    input_descriptor_id: String,
    path: &JsonPath,
) -> Result<&'a serde_json::Value> {
    path.query(&presentation_response.presentations)
        .at_most_one()
        .map_err(|e| {
            ParseSnafu {
                details: format!(
                    "Requested presentation \"{}\" not found by path {}: {}",
                    input_descriptor_id,
                    sanitize_log_msg(&path.to_string()),
                    e
                ),
            }
            .build()
        })?
        .ok_or(
            ParseSnafu {
                details: format!(
                    "Requested presentation \"{}\" not found by path {}",
                    input_descriptor_id,
                    sanitize_log_msg(&path.to_string())
                ),
            }
            .build(),
        )
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
    let mut path = match index {
        Some(i) => format!("$[{i}]"),
        None => "$".to_string(),
    };

    if let Presentation::LdpVp(_) = requested_presentation.presentation {
        path.push_str(".verifiableCredential");
    }

    let descriptor_map = DescriptorMap::new(
        &input_descriptor.id,
        format,
        JsonPath::from_str(&path).map_err(|e| {
            ParseSnafu {
                details: e.to_string(),
            }
            .build()
        })?,
    );

    submission.descriptor_map_mut().push(descriptor_map);

    Ok(())
}

#[instrument(level = Level::TRACE, err(), ret())]
pub fn split_to_inputs_for_pd(
    presentation_definition: &PresentationDefinition,
    claims_to_exclude: Option<&HashMap<String, Vec<String>>>,
) -> Result<Vec<PresentationInput>> {
    let mut inputs: Vec<PresentationInput> = vec![];
    for desc in presentation_definition.input_descriptors() {
        let mut updated_desc = desc.to_owned();

        if let Some(claims) = claims_to_exclude.and_then(|claims_map| claims_map.get(&desc.id)) {
            let constraints = filter_and_exclude_constraints(desc, claims)?;
            updated_desc = updated_desc.set_constraints(constraints);
        }

        inputs.push(updated_desc.try_into()?);
    }

    Ok(inputs)
}

impl TryInto<PresentationInput> for InputDescriptor {
    type Error = Error;

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn try_into(self) -> Result<PresentationInput> {
        let format = extract_format(&self.format)?.map(|format| format.name());

        let restrictions: Vec<PresentationRestriction> = self
            .constraints
            .fields()
            .iter()
            .map(resolve_credential_restriction)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        Ok(PresentationInput {
            id: self.id.to_owned(),
            format: format.to_owned(),
            restrictions,
        })
    }
}

fn filter_and_exclude_constraints(
    input_descriptor: &InputDescriptor,
    claims_to_exclude: &Vec<String>,
) -> Result<Constraints> {
    let constraints = &mut input_descriptor.constraints.to_owned();

    for (index, field) in constraints.fields().to_owned().iter().enumerate() {
        for claim in claims_to_exclude {
            if !field.path.contains(&JsonPath::from_str(claim).map_err(|e| {
                ParseSnafu {
                    details: format!(
                        "Could not parse excluded claim = '{claim}' as json path: {e}"
                    ),
                }
                .build()
            })?) {
                continue;
            }
            if !field.is_optional() {
                InvalidClaimsToExcludeSnafu {
                    details: format!("Claim = '{claim}' is not optional"),
                }
                .fail()?;
            }
            constraints.fields_mut().remove(index);
        }
    }

    Ok(constraints.to_owned())
}

#[instrument(level = Level::TRACE, err(), ret())]
fn extract_format(format_map: &ClaimFormatMap) -> Result<Option<ClaimFormat>> {
    //FIXME: Seems, it should be one format for specific Input Descriptor?
    let Some((format_name, format_payload)) = format_map.iter().next() else {
        return Ok(None);
    };

    let json = json!({ String::from(format_name.to_owned()): format_payload });

    let format = serde_json::from_value::<ClaimFormat>(json).map_err(|e| {
        ParseSnafu {
            details: format!("could not parse claim format: {e}"),
        }
        .build()
    })?;

    Ok(Some(format))
}

#[instrument(level = Level::TRACE, err(), ret())]
fn extract_input_descriptor<'a>(
    input_descriptor_id: &str,
    presentation_definition: &'a PresentationDefinition,
) -> Result<&'a InputDescriptor> {
    presentation_definition
        .input_descriptors()
        .iter()
        .find(|input_descriptor| input_descriptor.id == input_descriptor_id)
        .ok_or_else(|| {
            ParseSnafu {
                details: format!(
                    "Input descriptor with id {} not found",
                    sanitize_log_msg(input_descriptor_id)
                ),
            }
            .build()
        })
}

#[instrument(level = Level::TRACE, err(), ret())]
fn extract_vp_format(input_descriptor: &InputDescriptor) -> Result<ClaimFormatDesignation> {
    input_descriptor
        .format
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

#[instrument(level = Level::TRACE, err(), ret())]
fn resolve_credential_restriction(
    constraints: &ConstraintsField,
) -> Result<Vec<PresentationRestriction>> {
    let fields = (&constraints.path)
        .into_iter()
        .map(|path| path.to_string())
        .collect();

    let filter = constraints
        .filter()
        .map(|filter| serde_json::from_value(filter.clone()))
        .transpose()
        .map_err(|err| {
            ParseSnafu {
                details: format!("could not parse 'filter': {err}"),
            }
            .build()
        })?;

    let restrictions = build_restrictions(fields, filter, constraints.is_optional());

    Ok(restrictions)
}

fn generalize_json_path(path: &str) -> Result<String> {
    let path_segments: Vec<&str> = path.split('.').collect();

    let mut result = String::new();

    for segment in path_segments {
        if !result.is_empty() {
            result.push('.');
        }

        let open_bracket_pos = segment.find('[');
        let close_bracket_pos = segment.find(']');

        let segment = match (open_bracket_pos, close_bracket_pos) {
            (Some(open), Some(close)) => &segment.replace(&segment[open + 1..close], "*"),
            _ => segment,
        };

        result.push_str(segment);
    }

    let result = JsonPath::from_str(&result.to_string())
        .context(JsonPathCreationSnafu)?
        .to_string();
    Ok(result)
}

fn build_restrictions(
    fields: Vec<String>,
    filter: Option<FieldFilter>,
    optional: bool,
) -> Vec<PresentationRestriction> {
    let Some(filter_properties) = filter.and_then(|filter| filter.properties) else {
        return vec![PresentationRestriction {
            fields,
            value: None,
            optional,
        }];
    };

    match filter_properties {
        FieldFilterProperties::Const(const_) => vec![PresentationRestriction {
            fields,
            value: Some(PresentationRestrictionValue::Const(const_)),
            optional,
        }],
        FieldFilterProperties::Pattern(const_) => {
            vec![PresentationRestriction {
                fields,
                value: Some(PresentationRestrictionValue::Pattern(const_)),
                optional,
            }]
        }
        FieldFilterProperties::Items { enum_ } => {
            let fields: Vec<String> = fields.iter().map(|field| format!("{field}[*]")).collect();

            enum_
                .iter()
                .map(move |value| PresentationRestriction {
                    fields: fields.clone(),
                    value: Some(PresentationRestrictionValue::Const(value.to_owned())),
                    optional,
                })
                .collect()
        }
        FieldFilterProperties::Contains { const_ } => {
            let fields = fields.iter().map(|field| format!("{field}[*]")).collect();

            vec![PresentationRestriction {
                fields,
                value: Some(PresentationRestrictionValue::Const(const_)),
                optional,
            }]
        }
    }
}

pub fn validate_credential(
    credential: &Credential,
    presentation_input: &PresentationInput,
) -> crate::vault::Result<()> {
    let claims = credential.parse_claims().context(ClaimsParsingSnafu)?;

    if let Some(format) = &presentation_input.format {
        if !credential.format().to_string().cmp(format).is_eq() {
            UnsupportedCredentialFormatSnafu { format }.fail()?
        }
    }

    for pr in &presentation_input.restrictions {
        validate_restrictions(pr, &claims)?
    }

    Ok(())
}

fn validate_restrictions(
    presentation_restriction: &PresentationRestriction,
    claims: &Claims,
) -> crate::vault::Result<()> {
    for field in &presentation_restriction.fields {
        let json_path_field =
            jsonpath_rust::JsonPath::from_str(field).context(CannotCreateJSONPathSnafu)?;
        let json_claims = json!(claims.claims());
        let claims = json_path_field.find_slice(&json_claims);

        let has_value = claims.first().is_some_and(|claim| claim.has_value());
        if !has_value && !presentation_restriction.optional {
            continue;
        }

        if validate_claims_with_restriction_value(claims, presentation_restriction).is_ok() {
            return Ok(());
        }
    }
    ClaimsDidNotPassFilteringSnafu {
        details: &presentation_restriction.fields.join(", "),
    }
    .fail()
}

fn validate_claims_with_restriction_value(
    claims: Vec<JsonPathValue<Value>>,
    presentation_restriction: &PresentationRestriction,
) -> crate::vault::Result<()> {
    for claim in claims {
        if let Some(value) = &presentation_restriction.value {
            if value.validate_claim(claim.to_data().to_string()).is_ok() {
                return Ok(());
            }
        } else {
            return Ok(());
        }
    }
    ClaimsDidNotPassFilteringSnafu {
        details: &presentation_restriction.fields.join(", "),
    }
    .fail()?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inmem::kms::LocalKms;
    use crate::vc::core::tests::utils::CredTestCase;
    use openid4vp::core::{
        credential_format::ClaimFormatDesignation,
        input_descriptor::{ConstraintsField, InputDescriptor},
    };
    use rstest::rstest;
    use serde_json::{Value, json};
    use std::str::FromStr;

    #[tokio::test]
    async fn prepare_presentation_response_succeeds_handling_single_case() {
        let requested_presentation = create_requested_presentation_sdjwtvp(
            "descriptor_id",
            sample_sdjwt_presentation().as_str().unwrap(),
        );
        let presentation_definition = create_single_presentation_definition();

        let result =
            prepare_presentation_response(&[requested_presentation], &presentation_definition)
                .unwrap()
                .clone();

        let presentation_submission_id = result
            .clone()
            .presentation_submission
            .clone()
            .id()
            .to_owned();

        assert_eq!(
            result.clone(),
            PresentationResponse {
                presentations: sample_sdjwt_presentation(),
                presentation_submission: PresentationSubmission::new(
                    presentation_submission_id.to_owned(),
                    "presentation_definition_id".to_string(),
                    vec![DescriptorMap::new(
                        "descriptor_id".to_string(),
                        ClaimFormatDesignation::SdJwtVc,
                        JsonPath::from_str("$").unwrap()
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
            serde_json::to_value(&result[0].presentation).unwrap(),
            serde_json::to_value(presentation).unwrap(),
        )
    }

    #[tokio::test]
    async fn split_to_inputs_returns_correct_presentation_inputs_for_sdjwt() {
        let presentation_definition = create_single_presentation_definition();

        let result = split_to_inputs_for_pd(&presentation_definition, None).unwrap();

        assert_eq!(
            result,
            [PresentationInput {
                id: "descriptor_id".to_string(),
                format: Some("dc+sd-jwt".to_string()),
                restrictions: vec![PresentationRestriction {
                    fields: vec!["$.vct".to_string()],
                    value: Some(PresentationRestrictionValue::Const(
                        "https://credentials.example.com/identity_credential".to_string()
                    )),
                    optional: false,
                }],
            }]
        )
    }

    #[tokio::test]
    async fn split_to_inputs_works_for_ldpvc_with_enum_constraint() {
        let presentation_definition = PresentationDefinition::new(
            "presentation_definition_id".to_string(),
            sample_ldp_presentation_descriptor_with_enum(),
        );

        let result = split_to_inputs_for_pd(&presentation_definition, None).unwrap();

        assert_eq!(
            result,
            [PresentationInput {
                id: "resident-card".to_string(),
                format: Some("ldp_vc".to_string()),
                restrictions: vec![
                    PresentationRestriction {
                        fields: vec!["$.type[*]".to_string()],
                        value: Some(PresentationRestrictionValue::Const(
                            "VerifiableCredential".to_string()
                        )),
                        optional: false,
                    },
                    PresentationRestriction {
                        fields: vec!["$.type[*]".to_string()],
                        value: Some(PresentationRestrictionValue::Const(
                            "PermanentResidentCard".to_string()
                        )),
                        optional: false,
                    }
                ],
            }]
        )
    }

    #[tokio::test]
    async fn split_to_inputs_works_for_ldpvc_with_contains_constraint() {
        let presentation_definition = PresentationDefinition::new(
            "presentation_definition_id".to_string(),
            sample_ldp_presentation_descriptor_with_contains(),
        );

        let result = split_to_inputs_for_pd(&presentation_definition, None).unwrap();

        assert_eq!(
            result,
            [PresentationInput {
                id: "resident-card".to_string(),
                format: Some("ldp_vc".to_string()),
                restrictions: vec![PresentationRestriction {
                    fields: vec!["$.type[*]".to_string()],
                    value: Some(PresentationRestrictionValue::Const(
                        "PermanentResidentCard".to_string()
                    )),
                    optional: false,
                }],
            }]
        )
    }

    #[rstest]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[tokio::test]
    async fn credential_validated_using_disjunction(#[case] cred_test_case: CredTestCase) {
        let (credential, _) = cred_test_case.generate_vc(&LocalKms::new()).await;
        let mut presentation_input = cred_test_case.create_presentation_input();

        presentation_input.restrictions[0]
            .fields
            .insert(0, "$.field.will.pass.whilst.other.field.passes".to_string());
        validate_credential(&credential.credential, &presentation_input).unwrap()
    }
    #[rstest]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[tokio::test]
    #[should_panic(expected = "Claims did not pass filtering: $.field.will.not.pass")]
    async fn credential_validated_fails_on_non_existing_field(
        #[case] cred_test_case: CredTestCase,
    ) {
        let (credential, _) = cred_test_case.generate_vc(&LocalKms::new()).await;
        let mut presentation_input = cred_test_case.create_presentation_input();

        presentation_input.restrictions[0].fields = vec!["$.field.will.not.pass".to_string()];
        validate_credential(&credential.credential, &presentation_input).unwrap()
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
    #[should_panic(expected = "Requested presentation \"descriptor_id\" not found by path")]
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
    #[should_panic(expected = "Incorrect presentation format: expected SD-JWT string")]
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

    #[rstest]
    #[case::no_indices("$.root.child.grandchild", "$.root.child.grandchild")]
    #[case::single_index("$.root.child[0].grandchild", "$.root.child[*].grandchild")]
    #[case::multi_index("$.root.child[0].grandchild[1]", "$.root.child[*].grandchild[*]")]
    #[case::single_sigment("$[0]", "$[*]")]
    fn test_generalize_json_path(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(generalize_json_path(input).unwrap(), expected);
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
        .add_input_descriptor(create_input_descriptor(
            "descriptor_id_2",
            constraints.clone(),
            format.clone(),
        ))
        .add_input_descriptor(create_input_descriptor(
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
            "dc+sd-jwt": {
              "sd-jwt_alg_values": ["ES256", "EdDSA"],
              "kb-jwt_alg_values": ["ES256", "EdDSA"]
            }
        }))
        .unwrap()
    }

    fn create_constraints_field(path: &str, filter: Value) -> ConstraintsField {
        ConstraintsField::new(JsonPath::from_str(path).unwrap())
            .set_filter(&filter)
            .unwrap()
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
        DescriptorMap::new(id.to_string(), format, JsonPath::from_str(path).unwrap())
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
