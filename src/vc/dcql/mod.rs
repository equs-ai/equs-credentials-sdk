//! DIF DCQL related methods.

use crate::utils::json;
use crate::utils::logs::sanitize_log_msg;
use crate::vault::{
    CannotCreateJSONPathSnafu, ClaimsParsingSnafu, CredentialEntry,
    UnsupportedCredentialFormatSnafu,
};
use crate::vc::core::{PresentationInput, PresentationRestriction, PresentationRestrictionValue};
use crate::vc::{ClaimFormatDesignation, HasClaims, Presentation, RequestedPresentation};
use crate::vc::{Credential, HasVCFormat, JsonPath};
use common_macros::DebugError;
use openid4vp::core::dcql::{DcqlClaim, DcqlCredential, DcqlCredentialSet, PathValue, ValueType};
use serde_json::{Map, Value, json};
use snafu::{Location, ResultExt, Snafu};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::vec;

pub type DCQL = openid4vp::core::dcql::DCQL;
pub type DCQLCredential = DcqlCredential;

pub type NonEmptyVec<T> = openid4vp::utils::NonEmptyVec<T>;

#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Parse error: {details}"))]
    Parse {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("Not Found"))]
    NotFound,
}
pub type Result<T> = core::result::Result<T, Error>;

pub fn split_to_inputs_for_dcql(dcql_credentials: &[DcqlCredential]) -> Vec<PresentationInput> {
    dcql_credentials
        .iter()
        .map(|dc| PresentationInput {
            id: dc.id().as_str().to_string(),
            format: Some(dc.format().to_string()),
            restrictions: get_restrictions_for_dcql_credential(dc),
        })
        .collect()
}

fn get_restrictions_for_dcql_credential(
    credential: &DCQLCredential,
) -> Vec<PresentationRestriction> {
    let optional = credential.claim_sets().is_some();
    let mut restrictions = credential.claims().map_or(vec![], |claims| {
        claims
            .iter()
            .map(|claim| {
                let fields = vec![json::json_path_as_string(&claim.path().to_vec())];
                let value = claim
                    .values()
                    .and_then(|v| get_restriction_value_from_dcql_claim_values(v));
                PresentationRestriction {
                    fields,
                    value,
                    optional,
                }
            })
            .collect()
    });
    let type_restriction = get_restriction_for_type(credential);
    if let Some(type_restriction) = type_restriction {
        restrictions.push(type_restriction);
    }
    restrictions
}

fn get_restriction_for_type(credential: &DCQLCredential) -> Option<PresentationRestriction> {
    match credential.format() {
        ClaimFormatDesignation::SdJwtVc => credential.meta().vct_values().map(|vct_values| {
            let values = vct_values
                .iter()
                .map(|val| ValueType::String(val.to_string()))
                .collect::<Vec<_>>();
            let fields = vec![json::json_path_as_string(&vec![PathValue::String(
                "vct".to_string(),
            )])];

            PresentationRestriction {
                fields,
                value: get_restriction_value_from_dcql_claim_values(&values),
                optional: false,
            }
        }),
        ClaimFormatDesignation::LdpVc => credential.meta().type_values().map(|type_values| {
            let values = type_values
                .iter()
                .map(|vals| {
                    vals.iter()
                        .map(|v| {
                            let parts = v.splitn(2, '#').collect::<Vec<_>>();
                            if parts.len() < 2 {
                                v.to_string()
                            } else {
                                parts[1].to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            let fields = vec![json::json_path_as_string(&vec![
                PathValue::String("type".to_string()),
                PathValue::Null,
            ])];
            PresentationRestriction {
                fields,
                value: Some(PresentationRestrictionValue::ArrayOfValues(values)),
                optional: false,
            }
        }),
        _ => None,
    }
}
fn get_restriction_value_from_dcql_claim_values(
    values: &[ValueType],
) -> Option<PresentationRestrictionValue> {
    let value_strings = values
        .iter()
        .map(|v| match v {
            ValueType::String(s) => s.clone(),
            ValueType::Boolean(b) => b.to_string(),
            ValueType::Integer(i) => i.to_string(),
        })
        .collect::<Vec<String>>();
    if value_strings.is_empty() {
        None
    } else if value_strings.len() == 1 {
        Some(PresentationRestrictionValue::Const(
            value_strings[0].clone(),
        ))
    } else {
        let pattern = format!("^({})$", value_strings.join("|"));
        Some(PresentationRestrictionValue::Pattern(pattern))
    }
}

pub fn filter_claims_using_claim_sets(
    dcql_credential: &DCQLCredential,
    credential_entries: Vec<CredentialEntry>,
) -> Vec<CredentialEntry> {
    let Some(claim_sets) = dcql_credential.claim_sets() else {
        return credential_entries;
    };
    let Some(claims) = dcql_credential.claims() else {
        return credential_entries;
    };
    let claim_set_with_path = get_claim_set_with_path_instead_of_id(
        claims,
        claim_sets
            .iter()
            .map(|v| v.to_vec())
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let mut result: Vec<CredentialEntry> = Vec::new();
    for credential_entry in credential_entries {
        for set in claim_set_with_path.clone() {
            if check_cred_contains_all_paths(credential_entry.to_owned(), set).is_ok() {
                result.push(credential_entry);
                break;
            }
        }
    }
    result
}

fn get_claim_set_with_path_instead_of_id(
    claims: &[DcqlClaim],
    claim_sets: &[Vec<String>],
) -> Vec<Vec<String>> {
    let mut claim_id_to_path_map = HashMap::new();
    claims.iter().for_each(|c| {
        if let Some(id) = c.id() {
            let id = id.as_str();
            let path = json::json_path_as_string(&c.path().to_vec());
            claim_id_to_path_map.insert(id.to_string(), path);
        }
    });

    claim_sets
        .iter()
        .map(|set| {
            set.iter()
                .filter_map(|id| claim_id_to_path_map.get(id).cloned())
                .collect()
        })
        .collect()
}

fn check_cred_contains_all_paths(
    credential: CredentialEntry,
    set: Vec<String>,
) -> crate::vault::Result<()> {
    let raw_claims = credential
        .credential
        .parse_claims()
        .context(ClaimsParsingSnafu)?;
    for field in set {
        let json_path_field =
            jsonpath_rust::JsonPath::from_str(field.as_str()).context(CannotCreateJSONPathSnafu)?;
        let json_claims = json!(raw_claims.claims());
        let claims = json_path_field.find_slice(&json_claims);

        let has_value = claims.first().is_some_and(|claim| claim.has_value());
        if !has_value {
            return Err(crate::vault::Error::EmptyFields);
        }
    }
    Ok(())
}
pub fn filter_creds_with_cred_sets(
    id_to_ver_cred: &HashMap<String, CredentialEntry>,
    dcql: &DCQL,
) -> Result<Vec<DCQLCredential>> {
    let mut to_be_returned_cred_ids = HashSet::new();

    if let Some(credential_sets) = dcql.credential_sets() {
        for set in credential_sets {
            check_if_set_required_and_all_creds_exist(set, id_to_ver_cred)?;
            for option in set.options() {
                to_be_returned_cred_ids.extend(option.to_owned());
            }
        }
    } else {
        for dcql_credential in dcql.credentials() {
            if !id_to_ver_cred.contains_key(dcql_credential.id().as_str()) {
                NotFoundSnafu.fail()?
            }
            to_be_returned_cred_ids.insert(dcql_credential.id().as_str().to_string());
        }
    }

    let mut res = Vec::new();
    for id in to_be_returned_cred_ids {
        let cred = dcql
            .credentials()
            .iter()
            .find(|&c| c.id().as_str().cmp(&id) == Ordering::Equal);
        if let Some(c) = cred {
            res.push(c.to_owned());
        }
    }
    Ok(res)
}

fn check_if_set_required_and_all_creds_exist(
    set: &DcqlCredentialSet,
    id_to_cred: &HashMap<String, CredentialEntry>,
) -> Result<()> {
    let required = set.required().unwrap_or(&true).to_owned();
    let mut exists_any = false;
    for option in set.options() {
        let mut exists_all = true;
        for id in option {
            if !id_to_cred.contains_key(id) {
                exists_all = false;
            }
        }
        if exists_all {
            exists_any = true;
            break;
        }
    }
    if required && !exists_any {
        NotFoundSnafu.fail()?
    }
    Ok(())
}

pub(crate) fn prepare_vp_token_response_for_dcql(
    requested_presentations: &[RequestedPresentation],
) -> Result<Value> {
    let mut presentations: Map<String, Value> = Map::new();

    for presentation in requested_presentations.iter() {
        presentations.insert(
            presentation.id.clone(),
            serde_json::to_value(presentation.presentation.clone()).map_err(|err| {
                ParseSnafu {
                    details: format!("Presentation parse error: {err}"),
                }
                .build()
            })?,
        );
    }

    let presentations = Value::Object(presentations);

    Ok(presentations)
}

pub(crate) fn resolve_presentation_response(
    presentations: Value,
    dcql: &DCQL,
) -> Result<Vec<RequestedPresentation>> {
    let mut result: Vec<RequestedPresentation> = vec![];
    for credential_query in dcql.credentials() {
        let presentation = match credential_query.format() {
            ClaimFormatDesignation::SdJwtVc => {
                let path = JsonPath::parse(
                    json::json_path_as_string(&vec![PathValue::String(
                        credential_query.id().as_str().to_owned(),
                    )])
                    .as_str(),
                )
                .map_err(|e| {
                    ParseSnafu {
                        details: "Could not parse json path",
                    }
                    .build()
                })?;
                let prs_json = extract_json_presentation(
                    &presentations,
                    credential_query.id().as_str().to_owned(),
                    &path,
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
                let unwrapped_json = extract_json_presentation(
                    &presentations,
                    credential_query.id().as_str().to_string(),
                    &JsonPath::parse(format!("$.{}", credential_query.id().as_str()).as_str())
                        .map_err(|err| {
                            ParseSnafu {
                                details: format!(
                                    "Could not deserialize 'ldp_vc' presentation from json: {err}"
                                ),
                            }
                            .build()
                        })?,
                )
                .map_err(|err| {
                    ParseSnafu {
                        details: format!(
                            "Could not deserialize 'ldp_vc' presentation from json: {err}"
                        ),
                    }
                    .build()
                })?;
                let presentation =
                    serde_json::from_value(unwrapped_json.clone()).map_err(|err| {
                        ParseSnafu {
                            details: format!(
                                "Could not deserialize 'ldp_vc' presentation from json: {err}"
                            ),
                        }
                        .build()
                    })?;

                Presentation::LdpVp(presentation)
            }
            _ => FormatNotSupportedSnafu {
                format: String::from(credential_query.format().to_owned()),
            }
            .fail()?,
        };
        result.push(RequestedPresentation {
            id: credential_query.id().as_str().to_owned(),
            presentation,
            require_cryptographic_holder_binding: credential_query
                .require_cryptographic_holder_binding(),
        })
    }
    Ok(result)
}

fn extract_json_presentation<'a>(
    presentations: &'a Value,
    credential_id: String,
    path: &JsonPath,
) -> Result<&'a Value> {
    path.query(presentations)
        .at_most_one()
        .map_err(|e| {
            ParseSnafu {
                details: format!(
                    "Requested presentation \"{}\" not found by path {}: {}",
                    credential_id,
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
                    credential_id,
                    sanitize_log_msg(&path.to_string())
                ),
            }
            .build(),
        )
}

pub fn validate_credential_for_dcql(
    credential: &Credential,
    dcql_credential: &DcqlCredential,
) -> crate::vault::Result<()> {
    let raw_claims = credential.parse_claims().context(ClaimsParsingSnafu)?;
    if !credential
        .format()
        .to_string()
        .cmp(&dcql_credential.format().to_string())
        .is_eq()
    {
        UnsupportedCredentialFormatSnafu {
            format: credential.format().to_string(),
        }
        .fail()?
    }

    //check if values given and fits
    let Some(dcql_claims) = dcql_credential.claims() else {
        return Ok(());
    };
    for dcql_claim in dcql_claims {
        let Some(values) = dcql_claim.values() else {
            continue;
        };
        let field = json::json_path_as_string(&dcql_claim.path().to_vec());
        let Ok(json_path_field) = jsonpath_rust::JsonPath::from_str(field.as_str()) else {
            continue;
        };
        let json_claims = json!(raw_claims.claims());
        let claims = json_path_field.find_slice(&json_claims);
        let Some(claim_value) = claims.first() else {
            continue;
        };
        if claim_value.has_value() {
            let mut is_value_equal = false;
            for claim in claims {
                let claim_string = claim.to_data().to_string();
                for value in values {
                    let value_string = match value {
                        ValueType::String(s) => s.clone(),
                        ValueType::Boolean(b) => b.to_string(),
                        ValueType::Integer(i) => i.to_string(),
                    };
                    let claim_string = claim_string.trim_matches('\"').trim();
                    if claim_string.cmp(value_string.as_str()).is_eq() {
                        is_value_equal = true;
                    }
                }
            }
            if !is_value_equal {
                return UnsupportedCredentialFormatSnafu {
                    format: credential.format().to_string(),
                }
                .fail()?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::crypto::Key;
    use crate::did::universal::UniversalResolver;
    use crate::inmem::kms::LocalKms;
    use crate::kms::KeyType;
    use crate::utils::test_utils::create_did_url_and_key_handle;
    use crate::vault::CredentialEntry;
    use crate::vc::claims::{Claim, Claims};
    use crate::vc::core::tests::utils::CredTestCase;
    use crate::vc::core::{
        PresentationInput, PresentationRestriction, PresentationRestrictionValue,
    };
    use crate::vc::dcql::{
        DCQL, DCQLCredential, filter_claims_using_claim_sets, filter_creds_with_cred_sets,
        resolve_presentation_response, split_to_inputs_for_dcql, validate_credential_for_dcql,
    };
    use crate::vc::formats::json_ld_vc::JsonLdAPI;
    use crate::vc::formats::sd_jwt_vc::{EXP_CLAIM, IAT_CLAIM, NBF_CLAIM, SdJwtAPI};
    use crate::vc::{ClaimFormatDesignation, Credential, VCFormatsAPI, VCMetadata};
    use iref::IriRefBuf;
    use openid4vp::core::dcql::DcqlCredentialSet;
    use rstest::rstest;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::ops::Add;
    use std::str::FromStr;
    use time::OffsetDateTime;

    #[rstest]
    #[case(create_simple_dcql_case())]
    #[case(get_complex_sdjwt_dcql_case())]
    fn split_to_inputs_returns_correct_presentation_inputs(
        #[case] test_case: (Vec<DCQLCredential>, Vec<PresentationInput>),
    ) {
        let (dcql_creds, expected) = test_case;
        let actual = split_to_inputs_for_dcql(&dcql_creds);
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_filter_claims_using_claim_sets() {
        let cred_entries = get_credential_entries().await;
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {},
                    "claims": [
                        {"id": "b", "path": ["postal_code"], "values": ["90210", "90211"]},
                        {"id": "d", "path": ["region", 0, "street"]},
                        {"id": "e", "path": ["date_of_birth", null, "day"]}
                    ],
                    "claim_sets": [
                        ["b", "d"],
                        ["d", "e"],
                        ["e", "b"],
                    ]
                }
        ))
        .unwrap();

        let actual = filter_claims_using_claim_sets(&dcql_credential, cred_entries.clone());
        let expected = vec![
            cred_entries[0].clone(),
            cred_entries[1].clone(),
            cred_entries[2].clone(),
        ];
        for (a, e) in actual.iter().zip(expected.iter()) {
            assert_eq!(a.id, e.id);
        }

        let dcql_credential_without_claim_sets: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {},
                    "claims": [
                        {"id": "b", "path": ["postal_code"], "values": ["90210", "90211"]},
                        {"id": "d", "path": ["region", 0, "street"]},
                        {"id": "e", "path": ["date_of_birth", null, "day"]}
                    ]
                }
        ))
        .unwrap();
        let actual = filter_claims_using_claim_sets(
            &dcql_credential_without_claim_sets,
            cred_entries.clone(),
        );
        assert_eq!(actual.len(), 5);

        let dcql_credential_without_claims: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {}
                }
        ))
        .unwrap();
        let actual =
            filter_claims_using_claim_sets(&dcql_credential_without_claims, cred_entries.clone());
        assert_eq!(actual.len(), 5);
    }

    #[tokio::test]
    async fn check_filter_creds_with_cred_sets() {
        let map = get_id_to_cred_map().await;
        let credentials: Vec<DCQLCredential> = serde_json::from_value(json!(
            [
                    {
                        "id": "1",
                        "format": "dc+sd-jwt",
                        "meta": {}
                    },
                    {
                        "id": "2",
                        "format": "dc+sd-jwt",
                        "meta": {}
                    },
                    {
                        "id": "3",
                        "format": "dc+sd-jwt",
                        "meta": {}
                    },
                    {
                        "id": "4",
                        "format": "dc+sd-jwt",
                        "meta": {}
                    },
                    {
                        "id": "5",
                        "format": "dc+sd-jwt",
                        "meta": {}
                    },
                    {
                        "id": "6",
                        "format": "dc+sd-jwt",
                        "meta": {}
                    },
            ]
        ))
        .unwrap();

        let credential_sets: Vec<DcqlCredentialSet> = serde_json::from_value(json!(
            [
                    {
                      "purpose": "Identification",
                      "options": [
                        [ "1" ],
                        [ "2" ],
                        [ "4", "3" ]
                      ]
                    },
                    {
                      "purpose": "Show your rewards card",
                      "required": false,
                      "options": [
                        [ "3", "4", "5" ]
                      ]
                    }
                ]
        ))
        .unwrap();

        let mut dcql = DCQL::new(credentials.clone().try_into().unwrap());
        for set in credential_sets {
            dcql = dcql.add_credential_set(set.clone());
        }

        let result = filter_creds_with_cred_sets(&map, &dcql).unwrap();
        assert_eq!(result.len(), 5);

        let credential_sets_required: Vec<DcqlCredentialSet> = serde_json::from_value(json!(
            [
                    {
                      "purpose": "Show your rewards card",
                      "required": true,
                      "options": [
                        [ "3", "4", "7" ],
                        [ "6" ],
                      ]
                    }
                ]
        ))
        .unwrap();
        let mut dcql = DCQL::new(credentials.try_into().unwrap());
        for set in credential_sets_required {
            dcql = dcql.add_credential_set(set.clone());
        }
        let result = filter_creds_with_cred_sets(&map, &dcql);
        assert!(result.is_err());
    }

    #[rstest]
    #[case(sample_sdjwt_presentation_for_dcql(), ClaimFormatDesignation::SdJwtVc)]
    #[case(sample_ldp_vc_presentation_for_dcql(), ClaimFormatDesignation::LdpVc)]
    fn resolve_presentation_response_works_correctly_with_correct_data(
        #[case] test_case: (Value, Value),
        #[case] format: ClaimFormatDesignation,
    ) {
        let (presentation, expected) = test_case;
        let format_str = format.to_string();
        let credential: DCQLCredential = serde_json::from_value(json!(
            {
                "id": "id",
                "format": format_str,
                "meta": {}
            }
        ))
        .unwrap();
        let dcql = DCQL::new(vec![credential].try_into().unwrap());
        let actual = resolve_presentation_response(presentation.clone(), &dcql).unwrap();
        assert_eq!(
            serde_json::to_value(&actual[0].presentation).unwrap(),
            expected,
        )
    }

    #[rstest]
    #[should_panic(expected = "Requested presentation \"not_correct_id\" not found by path")]
    fn resolve_presentation_response_returns_error_with_wrong_path() {
        let (presentation, _) = sample_sdjwt_presentation_for_dcql();
        let format_str = ClaimFormatDesignation::SdJwtVc.to_string();
        let credential: DCQLCredential = serde_json::from_value(json!(
            {
                "id": "not_correct_id",
                "format": format_str,
                "meta": {}
            }
        ))
        .unwrap();
        let dcql = DCQL::new(vec![credential].try_into().unwrap());
        let actual = resolve_presentation_response(presentation.clone(), &dcql).unwrap();
    }

    #[rstest]
    #[should_panic(expected = "Unsupported format")]
    fn resolve_presentation_response_returns_error_with_wrong_format() {
        let (presentation, _) = sample_sdjwt_presentation_for_dcql();
        let wrong_format_str = ClaimFormatDesignation::Jwt.to_string();
        let credential: DCQLCredential = serde_json::from_value(json!(
            {
                "id": "not_correct_id",
                "format": wrong_format_str,
                "meta": {
                    "vct_values": ["some_vct".to_string()]
                }
            }
        ))
        .unwrap();
        let dcql = DCQL::new(vec![credential].try_into().unwrap());
        let actual = resolve_presentation_response(presentation.clone(), &dcql).unwrap();
    }

    #[rstest]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[tokio::test]
    async fn credential_validated_using_disjunction(#[case] cred_test_case: CredTestCase) {
        let (credential, _) = cred_test_case.generate_vc(&LocalKms::new(), None).await;
        let dcql_credential: DCQLCredential = cred_test_case.create_dcql_credential();

        validate_credential_for_dcql(&credential.credential, &dcql_credential).unwrap()
    }

    fn sample_sdjwt_presentation_for_dcql() -> (Value, Value) {
        let presentation_for_dcql = json!(
        {"id":"eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVwbmhBQXI5Tk51TnJ6M1pydU5ibTY0NGk5aW9VYW1xSHBZQXBTNldSUVNlTiN6RG5hZXBuaEFBcjlOTnVOcnozWnJ1TmJtNjQ0aTlpb1VhbXFIcFlBcFM2V1JRU2VOIn0.eyJfc2QiOlsiTWdsdFNpQUczcUpCTWMyUXU0UnVDUk1RSl9PNzdBZTI5ak9MY0NtRFNLUSIsImhfRkFmTEdCeVVyWHo5dkRNRHN1QnZzd2k3UDBRdlRhT0dyTW5XbTlDbEkiLCJsUzJVaWhBeU1ieEZ1cUJrS1ZhTmJDbmE1UjA5U1dQcGpVOFc4eDliakNnIl0sImlhdCI6MTc0NzI2ODYxMywiZGF0ZSI6IjA5LzA5LzE5ODkiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlc2tNWUozUmNrdkUxeXJ4cE1mTmtXTkxBdnptVXhFQjJKb3o3ZlF4OHRMQXUiLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWVwbmhBQXI5Tk51TnJ6M1pydU5ibTY0NGk5aW9VYW1xSHBZQXBTNldSUVNlTiIsImV4cCI6MTc3ODgwNDYxMywibmJmIjoxNzQ3MjY4NjEzLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibGVGdmtuNFlKNGtUdE45MUVQZmU4ZlRuN1hQWm5kMUtQV0Yxd193cDhYSSIsInkiOiJUZ0lwNjlfV3oxODFCYlZMcHg5cE16SW5fQ0JWeGhMbXRvcUFueE90ZDIwIn19fQ.P4e1UwBcxKMFSPq3xm9fFLUn8gJI6LdUQVUD1eIQLZLakMja7af-blESspA2RYS0vJ3NrNqUgft3RZ2v5dKlEw~WyJIc3RSS2JWR3JmVkViMk5lYTBwT0JRIiwgIm5hbWUiLCAiSm9obiJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiT2dtazBIUlJPR1N5bDZaOWd1dTdydTFYOHR5VnZ1R0tsTXpkNkwwNUVubyIsIm5vbmNlIjoiN2dMaFFpdC1vY2FvMVNQejFKbWhyYm1GenNCelluak54ZVVnUHFWaWpzbyIsImlhdCI6MTc0NzI2ODYxMywiYXVkIjoiZGlkOmtleTp6RG5hZWdFYjRScWppR3ZHZ0xpWXFqYm05ckFjZzZ4ZmJHUG5MOXBrZnhma0F1M3ZrIn0.eauedo3Oz9aluDNN_xweJtDjXRjwyfKxqAmZjBARBWEvy6J09HhrrBHmS7Yr7LGG9FE27OXziV90ovnUv3M9sw"}
        );
        let presentation_result = sample_sdjwt_presentation();
        (presentation_for_dcql, presentation_result)
    }

    fn sample_sdjwt_presentation() -> Value {
        serde_json::to_value("eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVwbmhBQXI5Tk51TnJ6M1pydU5ibTY0NGk5aW9VYW1xSHBZQXBTNldSUVNlTiN6RG5hZXBuaEFBcjlOTnVOcnozWnJ1TmJtNjQ0aTlpb1VhbXFIcFlBcFM2V1JRU2VOIn0.eyJfc2QiOlsiTWdsdFNpQUczcUpCTWMyUXU0UnVDUk1RSl9PNzdBZTI5ak9MY0NtRFNLUSIsImhfRkFmTEdCeVVyWHo5dkRNRHN1QnZzd2k3UDBRdlRhT0dyTW5XbTlDbEkiLCJsUzJVaWhBeU1ieEZ1cUJrS1ZhTmJDbmE1UjA5U1dQcGpVOFc4eDliakNnIl0sImlhdCI6MTc0NzI2ODYxMywiZGF0ZSI6IjA5LzA5LzE5ODkiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlc2tNWUozUmNrdkUxeXJ4cE1mTmtXTkxBdnptVXhFQjJKb3o3ZlF4OHRMQXUiLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWVwbmhBQXI5Tk51TnJ6M1pydU5ibTY0NGk5aW9VYW1xSHBZQXBTNldSUVNlTiIsImV4cCI6MTc3ODgwNDYxMywibmJmIjoxNzQ3MjY4NjEzLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibGVGdmtuNFlKNGtUdE45MUVQZmU4ZlRuN1hQWm5kMUtQV0Yxd193cDhYSSIsInkiOiJUZ0lwNjlfV3oxODFCYlZMcHg5cE16SW5fQ0JWeGhMbXRvcUFueE90ZDIwIn19fQ.P4e1UwBcxKMFSPq3xm9fFLUn8gJI6LdUQVUD1eIQLZLakMja7af-blESspA2RYS0vJ3NrNqUgft3RZ2v5dKlEw~WyJIc3RSS2JWR3JmVkViMk5lYTBwT0JRIiwgIm5hbWUiLCAiSm9obiJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiT2dtazBIUlJPR1N5bDZaOWd1dTdydTFYOHR5VnZ1R0tsTXpkNkwwNUVubyIsIm5vbmNlIjoiN2dMaFFpdC1vY2FvMVNQejFKbWhyYm1GenNCelluak54ZVVnUHFWaWpzbyIsImlhdCI6MTc0NzI2ODYxMywiYXVkIjoiZGlkOmtleTp6RG5hZWdFYjRScWppR3ZHZ0xpWXFqYm05ckFjZzZ4ZmJHUG5MOXBrZnhma0F1M3ZrIn0.eauedo3Oz9aluDNN_xweJtDjXRjwyfKxqAmZjBARBWEvy6J09HhrrBHmS7Yr7LGG9FE27OXziV90ovnUv3M9sw")
            .unwrap()
    }

    fn sample_ldp_vc_presentation_for_dcql() -> (Value, Value) {
        let presentation_for_dcql = serde_json::to_value(json!(
            {"id":{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"holder":"did:key:zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ","verifiableCredential":{"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/citizenship/v1"],"type":["VerifiableCredential","PermanentResident"],"credentialSubject":{"givenName":"John","type":["PermanentResident","Person"],"birthDate":"09/09/1989","familyName":"Doe","id":"did:key:zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ"},"issuer":"did:key:zDnaeryTefzWK446XPbJwNkLyXiLhPcEnkfxYVyRbS8Vk6U8r","issuanceDate":"2025-05-15T06:22:50.399115247Z","expirationDate":"2030-05-14T06:22:50.399115247Z","proof":{"type":"EcdsaSecp256r1Signature2019","created":"2025-05-15T06:22:50.399Z","verificationMethod":"did:key:zDnaeryTefzWK446XPbJwNkLyXiLhPcEnkfxYVyRbS8Vk6U8r#zDnaeryTefzWK446XPbJwNkLyXiLhPcEnkfxYVyRbS8Vk6U8r","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..2WBzR1pbcRqzt2YJ-B9Kts663M_8jtNi8inUTOPloPpNqMufiNY83MLE-dx_m4g6OXddXgrsJIziOHCAiH3bXA"}},"proof":{"type":"EcdsaSecp256r1Signature2019","created":"2025-05-15T06:22:50.421Z","verificationMethod":"did:key:zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ#zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ","proofPurpose":"assertionMethod","nonce":"7CbUWaXwH5z14AYNj8FZjvfRZvHIf5o8fi-3XshrlwU","jws":"eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..rPb9wUX15ByHLEGjcl5oYpH0EzOkGGYHrBm22OERyqvTBD-akjAHO-HUB7W6gcd_fAhbmnCL8A0L36RVir5LXg"}}}
        )).unwrap();
        let presentation_result = sample_ldp_vc_presentation();
        (presentation_for_dcql, presentation_result)
    }

    fn sample_ldp_vc_presentation() -> Value {
        serde_json::to_value(json!(
            {"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"holder":"did:key:zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ","verifiableCredential":{"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/citizenship/v1"],"type":["VerifiableCredential","PermanentResident"],"credentialSubject":{"givenName":"John","type":["PermanentResident","Person"],"birthDate":"09/09/1989","familyName":"Doe","id":"did:key:zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ"},"issuer":"did:key:zDnaeryTefzWK446XPbJwNkLyXiLhPcEnkfxYVyRbS8Vk6U8r","issuanceDate":"2025-05-15T06:22:50.399115247Z","expirationDate":"2030-05-14T06:22:50.399115247Z","proof":{"type":"EcdsaSecp256r1Signature2019","created":"2025-05-15T06:22:50.399Z","verificationMethod":"did:key:zDnaeryTefzWK446XPbJwNkLyXiLhPcEnkfxYVyRbS8Vk6U8r#zDnaeryTefzWK446XPbJwNkLyXiLhPcEnkfxYVyRbS8Vk6U8r","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..2WBzR1pbcRqzt2YJ-B9Kts663M_8jtNi8inUTOPloPpNqMufiNY83MLE-dx_m4g6OXddXgrsJIziOHCAiH3bXA"}},"proof":{"type":"EcdsaSecp256r1Signature2019","created":"2025-05-15T06:22:50.421Z","verificationMethod":"did:key:zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ#zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ","proofPurpose":"assertionMethod","nonce":"7CbUWaXwH5z14AYNj8FZjvfRZvHIf5o8fi-3XshrlwU","jws":"eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..rPb9wUX15ByHLEGjcl5oYpH0EzOkGGYHrBm22OERyqvTBD-akjAHO-HUB7W6gcd_fAhbmnCL8A0L36RVir5LXg"}}
        )).unwrap()
    }

    fn create_simple_dcql_case() -> (Vec<DCQLCredential>, Vec<PresentationInput>) {
        let credential = serde_json::from_value::<DCQLCredential>(json!(
                      {
                          "id": "pid",
                          "format": "dc+sd-jwt",
                          "meta": {
                            "vct_values": ["vct1", "vct2"],
                          },
                          "claims": [
                          {"path": ["username"]},
                          {"path": ["birthDate"]},
                          {"path": ["email", "work"]}
                          ]
                      }
        ))
        .unwrap();
        let pres_input = PresentationInput {
            id: "pid".to_string(),
            format: Some("dc+sd-jwt".to_string()),
            restrictions: vec![
                PresentationRestriction {
                    fields: vec!["$.username".to_string()],
                    value: None,
                    optional: false,
                },
                PresentationRestriction {
                    fields: vec!["$.birthDate".to_string()],
                    value: None,
                    optional: false,
                },
                PresentationRestriction {
                    fields: vec!["$.email.work".to_string()],
                    value: None,
                    optional: false,
                },
                PresentationRestriction {
                    fields: vec!["$.vct".to_string()],
                    value: Some(PresentationRestrictionValue::Pattern(
                        "^(vct1|vct2)$".to_string(),
                    )),
                    optional: false,
                },
            ],
        };
        (vec![credential], vec![pres_input])
    }

    fn get_complex_sdjwt_dcql_case() -> (Vec<DCQLCredential>, Vec<PresentationInput>) {
        let credentials: Vec<DCQLCredential> = serde_json::from_value(json!(
            [
                {
                  "id": "pid",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["https://credentials.example.com/identity_credential"]
                  },
                  "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]}
                  ]
                },
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {},
                    "claims": [
                        {"id": "b", "path": ["postal_code"], "values": ["90210", "90211"]},
                        {"id": "d", "path": ["region", 0, "street"]},
                        {"id": "e", "path": ["date_of_birth", null, "day"]}
                    ],
                    "claim_sets": [
                        ["a", "c", "d", "e"],
                        ["a", "b", "e"]
                    ]
                },
                {
                    "id": "pid3",
                    "format": "dc+sd-jwt",
                    "meta": {}
                }
            ]
        ))
        .unwrap();

        let first_pi = PresentationInput {
            id: "pid".to_string(),
            format: Some("dc+sd-jwt".to_string()),
            restrictions: vec![
                PresentationRestriction {
                    fields: vec!["$.given_name".to_string()],
                    value: None,
                    optional: false,
                },
                PresentationRestriction {
                    fields: vec!["$.family_name".to_string()],
                    value: None,
                    optional: false,
                },
                PresentationRestriction {
                    fields: vec!["$.address.street_address".to_string()],
                    value: None,
                    optional: false,
                },
                PresentationRestriction {
                    fields: vec!["$.vct".to_string()],
                    value: Some(PresentationRestrictionValue::Const(
                        "https://credentials.example.com/identity_credential".to_string(),
                    )),
                    optional: false,
                },
            ],
        };

        let second_pi = PresentationInput {
            id: "pid2".to_string(),
            format: Some("dc+sd-jwt".to_string()),
            restrictions: vec![
                PresentationRestriction {
                    fields: vec!["$.postal_code".to_string()],
                    value: Some(PresentationRestrictionValue::Pattern(
                        "^(90210|90211)$".to_string(),
                    )),
                    optional: true,
                },
                PresentationRestriction {
                    fields: vec!["$.region[0].street".to_string()],
                    value: None,
                    optional: true,
                },
                PresentationRestriction {
                    fields: vec!["$.date_of_birth[*].day".to_string()],
                    value: None,
                    optional: true,
                },
            ],
        };

        let third_pi = PresentationInput {
            id: "pid3".to_string(),
            format: Some("dc+sd-jwt".to_string()),
            restrictions: vec![],
        };

        (credentials, vec![first_pi, second_pi, third_pi])
    }

    async fn get_id_to_cred_map() -> HashMap<String, CredentialEntry> {
        let ids = ["1", "2", "3", "4", "5"];
        let cred_entries: Vec<CredentialEntry> = get_credential_entries().await;
        let mut map = HashMap::new();
        for (index, &id) in ids.iter().enumerate() {
            map.insert(id.to_string(), cred_entries[index].clone());
        }
        map
    }
    async fn get_credential_entries() -> Vec<CredentialEntry> {
        let claims_vec: Vec<Claims> = serde_json::from_value(json!(
            [
                {
                    "given_name": "John",
                    "family_name": "Doe",
                    "dob": "09/09/1989",
                    "postal_code": "90210",
                    "region": [
                        {
                            "street": "1"
                        },
                        {
                            "street": "1"
                        },
                        {
                            "street": "1"
                        }
                    ]
                },
                {
                    "birthCountry": "Arcadia",
                    "date_of_birth": [
                        {
                            "day": 1,
                        },
                        {
                            "day": 2,
                        }
                    ],
                    "region": [
                        {
                            "street": "1"
                        },
                        {
                            "street": "1"
                        },
                        {
                            "street": "1"
                        }
                    ]
                },
                {
                    "date_of_birth": [
                        {
                            "day": 1,
                        },
                        {
                            "day": 2,
                        }
                    ],
                    "postal_code": "90210",
                    "name": "Some name",
                },
                {
                    "given_name": "John",
                    "family_name": "Doe",
                    "dob": "09/09/1989",
                },
                {
                    "givenName": {},
                  "residentSince": {},
                  "birthDate": {},
                  "birthCountry": {},
                  "familyName": {},
                  "gender": {},
                  "commuterClassification": {},
                  "gpa": {}
                }
            ]
        ))
        .unwrap();

        let mut result: Vec<CredentialEntry> = Vec::new();
        for (i, claim) in claims_vec.iter().enumerate() {
            result.push(
                get_credential_entry(claim.to_owned(), ClaimFormatDesignation::SdJwtVc, i).await,
            );
        }
        result
    }
    async fn get_credential_entry(
        mut claims: Claims,
        format: ClaimFormatDesignation,
        index: usize,
    ) -> CredentialEntry {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let iss_jwk = iss_kh.jwk().unwrap();

        let exp = OffsetDateTime::now_utc()
            .add(time::Duration::days(365))
            .unix_timestamp();
        let nbf = OffsetDateTime::now_utc()
            .add(time::Duration::days(1))
            .unix_timestamp();
        let iat = OffsetDateTime::now_utc().unix_timestamp();
        claims.insert(EXP_CLAIM.to_string(), Claim::Int(exp));
        claims.insert(NBF_CLAIM.to_string(), Claim::Int(nbf));
        claims.insert(IAT_CLAIM.to_string(), Claim::Int(iat));
        match format {
            ClaimFormatDesignation::SdJwtVc => {
                let vc_metadata = sample_vc_metadata_with_empty_disclosures();
                let vc = SdJwtAPI::create_vc(
                    claims,
                    (&iss_did_url, iss_kh),
                    (&hld_did_url, hld_kh.clone()),
                    vc_metadata,
                    UniversalResolver::default(),
                )
                .await
                .unwrap();
                CredentialEntry {
                    credential: Credential::SdJwt(vc),
                    kid: index.to_string(),
                    id: index.to_string(),
                }
            }
            // we need only SdJwtVc and LdpVc formats
            _ => {
                let vc_meta = sample_vc_meta_for_ldp_vc();
                let vc = JsonLdAPI::create_vc(
                    claims.clone(),
                    (&iss_did_url, iss_kh),
                    (&hld_did_url, hld_kh.clone()),
                    vc_meta,
                    UniversalResolver::default(),
                )
                .await
                .unwrap();
                CredentialEntry {
                    credential: Credential::LdpVc(vc),
                    kid: "stb_id".to_string(),
                    id: "stub_id".to_string(),
                }
            }
        }
    }

    fn sample_vc_metadata_with_empty_disclosures() -> VCMetadata {
        VCMetadata {
            vct: "https://issuer.net/cred_schema".to_owned(),
            lifetime: time::Duration::days(365),
            disclosures: vec![],
            credential_status: None,
        }
    }

    fn sample_vc_meta_for_ldp_vc() -> crate::vc::formats::json_ld_vc::VCMetadata {
        crate::vc::formats::json_ld_vc::VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec!["PermanentResidentCard".to_string()],
            time::Duration::days(5 * 365),
        )
        .unwrap()
    }
}
