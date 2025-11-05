//! DIF DCQL related methods.

use crate::utils::json;
use crate::utils::logs::sanitize_log_msg;
use crate::vault::{
    CannotCreateJSONPathSnafu, ClaimsParsingSnafu, CredentialEntry,
    UnsupportedCredentialFormatSnafu,
};
use crate::vc::claims::Claim;
use crate::vc::core::{PresentationInput, PresentationRestriction, PresentationRestrictionValue};
use crate::vc::{ClaimFormatDesignation, HasClaims, Presentation, RequestedPresentation};
use crate::vc::{Credential, HasVCFormat, JsonPath};
use common_macros::DebugError;
use openid4vp::core::dcql::{DcqlClaim, DcqlCredential, DcqlCredentialSet, PathValue, ValueType};
use serde_json::{Value, json};
use snafu::{Location, ResultExt, Snafu};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::str::FromStr;
use std::vec;

pub type DCQL = openid4vp::core::dcql::DCQL;
pub type DCQLCredential = DcqlCredential;
pub type DCQLCredentialID = openid4vp::core::dcql::ID;
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
    #[snafu(display("Credential query validation error, query id = {query_id}: {details}"))]
    CredentialQueryValidation {
        query_id: String,
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Credential claim sets validation error, claim set = {}: {details}", claim_set.join(", ")))]
    CredentialClaimSetValidation {
        claim_set: Vec<String>,
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Credential sets validation error, credential set-option = {}: {details}", set_option.join(", ")))]
    CredentialSetsValidation {
        set_option: Vec<String>,
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
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
    id_to_ver_cred: &HashMap<String, Vec<CredentialEntry>>,
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
    id_to_cred: &HashMap<String, Vec<CredentialEntry>>,
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
    dcql_credentials: &NonEmptyVec<DCQLCredential>,
) -> Result<Value> {
    let cred_id_to_multiple: HashMap<&str, bool> = HashMap::from_iter(
        dcql_credentials
            .iter()
            .map(|c| (c.id().as_str(), c.multiple().unwrap_or_default())),
    );
    let mut presentations: HashMap<String, Vec<Value>> = HashMap::new();

    for presentation in requested_presentations.iter() {
        let json_presentation =
            serde_json::to_value(presentation.presentation.clone()).map_err(|err| {
                ParseSnafu {
                    details: format!("Presentation parse error: {err}"),
                }
                .build()
            })?;

        presentations
            .entry(presentation.id.clone())
            .and_modify(|json_presentations| {
                if let Some(true) = cred_id_to_multiple.get(presentation.id.as_str()) {
                    json_presentations.push(json_presentation.clone());
                }
            })
            .or_insert(vec![json_presentation]);
    }

    let presentations = serde_json::to_value(presentations).map_err(|err| {
        ParseSnafu {
            details: format!("Could not serialize presentations to json: {err}"),
        }
        .build()
    })?;

    Ok(presentations)
}

pub(crate) fn resolve_presentation_response(
    presentations: Value,
    dcql: &DCQL,
) -> Result<Vec<RequestedPresentation>> {
    let mut result: Vec<RequestedPresentation> = vec![];
    for credential_query in dcql.credentials() {
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

        let extracted_presentations = get_presentations_by_path(
            &presentations,
            credential_query.id().as_str().to_owned(),
            &path,
        )?;

        let mut presentation_results = Vec::new();
        match credential_query.format() {
            ClaimFormatDesignation::SdJwtVc => {
                for sd_jwt_json in extracted_presentations {
                    let sd_jwt = sd_jwt_json.as_str().ok_or(
                        ParseSnafu {
                            details: "Incorrect presentation format: expected SD-JWT string"
                                .to_string(),
                        }
                        .build(),
                    )?;
                    presentation_results.push(Presentation::SdJwtVp(sd_jwt.to_string()))
                }
            }
            ClaimFormatDesignation::LdpVc => {
                for ldp_vc_json in extracted_presentations {
                    let ldp_vc = serde_json::from_value(ldp_vc_json.clone()).map_err(|err| {
                        ParseSnafu {
                            details: format!(
                                "Could not deserialize 'ldp_vc' presentation from json: {err}"
                            ),
                        }
                        .build()
                    })?;

                    presentation_results.push(Presentation::LdpVp(ldp_vc))
                }
            }
            _ => FormatNotSupportedSnafu {
                format: String::from(credential_query.format().to_owned()),
            }
            .fail()?,
        };

        for presentation in presentation_results {
            result.push(RequestedPresentation {
                id: credential_query.id().as_str().to_owned(),
                presentation,
                require_cryptographic_holder_binding: credential_query
                    .require_cryptographic_holder_binding(),
            })
        }
    }
    Ok(result)
}

fn get_presentations_by_path<'a>(
    presentations: &'a Value,
    credential_id: String,
    path: &JsonPath,
) -> Result<&'a Vec<Value>> {
    let root = path
        .query(presentations)
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
        )?;

    root.as_array().ok_or(
        ParseSnafu {
            details: "Could not parse presentations as array of json".to_string(),
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

pub fn validate_credentials(dcql: &DCQL, credentials: &HashMap<String, Vec<Claim>>) -> Result<()> {
    if let Some(credential_sets) = dcql.credential_sets() {
        for set in credential_sets {
            validate_against_credential_set(credentials, dcql, set)?
        }

        return Ok(());
    }

    for query in dcql.credentials() {
        let creds = credentials.get(query.id().as_str()).ok_or_else(|| {
            CredentialQueryValidationSnafu {
                query_id: query.id().as_str().to_string(),
                details: format!(
                    "Credential(s) for credential-query with id = {} not found",
                    query.id().as_str()
                ),
            }
            .build()
        })?;

        validate_against_credential_query(creds, query)?;
    }

    Ok(())
}

fn validate_against_credential_set(
    credentials: &HashMap<String, Vec<Claim>>,
    dcql: &DCQL,
    set: &DcqlCredentialSet,
) -> Result<()> {
    if !set.required().unwrap_or(&true) {
        return Ok(());
    }

    let mut result = Ok(());
    for option in set.options() {
        result = validate_against_credential_set_option(credentials, dcql, option);
        if result.is_ok() {
            return Ok(());
        }
    }

    result
}

fn validate_against_credential_set_option(
    credentials: &HashMap<String, Vec<Claim>>,
    dcql: &DCQL,
    option: &NonEmptyVec<String>,
) -> Result<()> {
    for id in option {
        let Some(creds) = credentials.get(id.as_str()) else {
            CredentialSetsValidationSnafu {
                set_option: option.clone().to_vec(),
                details: format!("Credential(s) for credential-query with id = {id} not found"),
            }
            .fail()?
        };
        let Some(query) = dcql.credentials().iter().find(|q| q.id().as_str() == id) else {
            CredentialSetsValidationSnafu {
                set_option: option.clone().to_vec(),
                details: format!(
                    "Credential-query with id = {id} not found in dcql credential queries"
                ),
            }
            .fail()?
        };

        let cred_query_result = validate_against_credential_query(creds, query);
        if let Err(err) = cred_query_result {
            CredentialSetsValidationSnafu {
                set_option: option.clone().to_vec(),
                details: err.to_string(),
            }
            .fail()?
        }
    }

    Ok(())
}

fn validate_against_credential_query(
    credentials: &Vec<Claim>,
    query: &DcqlCredential,
) -> Result<()> {
    validate_against_credential_types(credentials, query)?;

    let Some(query_claims) = query.claims() else {
        return Ok(());
    };

    if let Some(claim_sets) = query.claim_sets() {
        validate_against_claims_set(query.id(), credentials, claim_sets, query_claims)?;

        return Ok(());
    }

    for claim_query in query_claims {
        validate_claim_path(query.id(), credentials, claim_query)?;
    }

    Ok(())
}

fn validate_against_claims_set(
    query_id: &DCQLCredentialID,
    credentials: &Vec<Claim>,
    claims_sets: &NonEmptyVec<NonEmptyVec<String>>,
    query_claims: &NonEmptyVec<DcqlClaim>,
) -> Result<()> {
    let mut claim_set_result = Ok(());

    for claim_set in claims_sets {
        let claims_in_set: Vec<&DcqlClaim> = claim_set
            .iter()
            .filter_map(|claim_query| {
                query_claims.iter().find(|c| {
                    c.id()
                        .map(|id| id.as_str().eq(claim_query))
                        .unwrap_or_default()
                })
            })
            .collect();

        claim_set_result = validate_claim_set(query_id, credentials, &claims_in_set);
        if claim_set_result.is_ok() {
            return Ok(());
        }
    }

    if let Err(err) = claim_set_result {
        claim_set_result = Err(CredentialClaimSetValidationSnafu {
            claim_set: claims_sets.last().unwrap().to_vec(),
            details: err.to_string(),
        }
        .build());
    }

    claim_set_result
}

fn validate_claim_set(
    query_id: &DCQLCredentialID,
    credentials: &Vec<Claim>,
    claims_in_set: &[&DcqlClaim],
) -> Result<()> {
    for claim_query in claims_in_set {
        validate_claim_path(query_id, credentials, claim_query)?;
    }
    Ok(())
}

fn validate_claim_path(
    query_id: &DCQLCredentialID,
    credentials: &Vec<Claim>,
    claim_query: &DcqlClaim,
) -> Result<()> {
    let field = json::json_path_as_string(&claim_query.path().to_vec());
    let json_path_field = jsonpath_rust::JsonPath::from_str(field.as_str()).map_err(|e| {
        CredentialQueryValidationSnafu {
            query_id: query_id.as_str().to_string(),
            details: format!("Could not parse claim path as json path: {e}"),
        }
        .build()
    })?;

    for credential in credentials {
        let json_cred = json!(credential);
        let claims = json_path_field.find_slice_ptr(&json_cred);

        let claim_value = claims
            .first()
            .ok_or_else(|| {
                CredentialQueryValidationSnafu {
                    query_id: query_id.as_str().to_string(),
                    details: format!("Could not find any claim for required claim path = {field}"),
                }
                .build()
            })?
            .deref();

        if let Some(values) = claim_query.values() {
            let are_values_equal = values.iter().any(|v| match (v, claim_value) {
                (ValueType::String(v), Value::String(s)) => v.eq(s),
                (ValueType::Boolean(v), Value::Bool(b)) => v.eq(b),
                (ValueType::Integer(v), Value::Number(n)) => {
                    n.as_u64().map(|n| v.eq(&n)).unwrap_or(false)
                }
                // Values are not supported for other claim types than String, Boolean and Integer
                _ => false,
            });

            if !are_values_equal {
                CredentialQueryValidationSnafu {
                    query_id: query_id.as_str().to_string(),
                    details: format!("Claim value does not match required values of claim path = {}, required values = {}, actual value = {}",
                                     field,
                                     serde_json::to_string_pretty(&values).unwrap_or_default(),
                                     serde_json::to_string_pretty(&claim_value).unwrap_or_default()),
                }.fail()?
            }
        }
    }

    Ok(())
}

fn validate_against_credential_types(
    credentials: &Vec<Claim>,
    query: &DCQLCredential,
) -> Result<()> {
    match query.format() {
        ClaimFormatDesignation::SdJwtVc => {
            let mut actual_vcts = vec![];
            for credential in credentials {
                let vct = credential
                    .get("vct")
                    .and_then(|vct| vct.as_str().map(|vct_str| vct_str.to_string()))
                    .ok_or_else(|| {
                        CredentialQueryValidationSnafu {
                            query_id: query.id().as_str().to_string(),
                            details: "Could not parse \"vct\" value from SD-JWT credential"
                                .to_string(),
                        }
                        .build()
                    })?;
                actual_vcts.push(vct);
            }

            let contains_vcts = query
                .meta()
                .vct_values()
                .map(|required_vcts| actual_vcts.iter().all(|vct| required_vcts.contains(vct)))
                .unwrap_or(true);

            if !contains_vcts {
                CredentialQueryValidationSnafu {
                    query_id: query.id().as_str().to_string(),
                    details: "Credential(s) does not contain required \"vct_values\"".to_string(),
                }
                .fail()?
            }
        }

        ClaimFormatDesignation::LdpVc => {
            for credential in credentials {
                let cred_types =
                    credential
                        .get("type")
                        .and_then(|t| t.as_vec())
                        .ok_or_else(|| {
                            CredentialQueryValidationSnafu {
                                query_id: query.id().as_str().to_string(),
                                details:
                                    "Could not parse \"type\" value from json-ld-vc credential"
                                        .to_string(),
                            }
                            .build()
                        })?;

                if let Some(type_values) = query.meta().type_values() {
                    let cred_type_strings: Vec<String> = cred_types
                        .iter()
                        .filter_map(|t| t.as_str().map(|s| s.to_string()))
                        .collect();

                    let has_required_types = type_values.iter().any(|required_types| {
                        required_types.iter().all(|rt| {
                            cred_type_strings
                                .contains(&rt.split('#').next_back().unwrap_or(rt).to_string())
                        })
                    });

                    if !has_required_types {
                        CredentialQueryValidationSnafu {
                            query_id: query.id().as_str().to_string(),
                            details: "Credential(s) does not contain required \"type_values\""
                                .to_string(),
                        }
                        .fail()?
                    }
                }
            }
        }

        _ => CredentialQueryValidationSnafu {
            query_id: query.id().as_str().to_string(),
            details: format!("Unsupported credential format {}", query.format()),
        }
        .fail()?,
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
        validate_credentials,
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

    #[test]
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

    #[test]
    #[should_panic(expected = "Unsupported format")]
    fn resolve_presentation_response_returns_error_with_wrong_format() {
        let (presentation, _) = sample_sdjwt_presentation_for_dcql();
        let wrong_format_str = ClaimFormatDesignation::Jwt.to_string();
        let credential: DCQLCredential = serde_json::from_value(json!(
            {
                "id": "id",
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

    #[rstest]
    #[case::validate_claims_success(dcql_with_claims())]
    #[case::validate_multi_claim_sets(dcql_with_claim_sets())]
    #[case::validate_ldp_vc_types(dcql_and_ldp_vc_credential())]
    #[case::validate_credential_sets(dcql_with_credential_sets())]
    #[tokio::test]
    async fn validate_claims_success(#[case] test_case: (DCQL, HashMap<String, Vec<Claim>>)) {
        let (dcql, credentials) = test_case;
        assert!(validate_credentials(&dcql, &credentials).is_ok());
    }

    #[rstest]
    #[should_panic(expected = "Credential(s) for credential-query with id = pid not found")]
    #[case::credentials_not_found(dcql_and_credential_with_mismatched_query_id())]
    #[should_panic(
        expected = "Claim value does not match required values of claim path = $.postal_code"
    )]
    #[case::mismatched_claim_values(dcql_and_credential_with_mismatched_values())]
    #[should_panic(expected = "Could not find any claim for required claim path = $.missing_field")]
    #[case::missing_required_claim(dcq_and_credential_with_missing_claims())]
    #[should_panic(expected = "Could not parse claim path as json path")]
    #[case::invalid_claim_path(dcql_with_invalid_path())]
    #[should_panic(expected = "Could not parse \"vct\" value from SD-JWT credential")]
    #[case::credential_without_type(dcql_and_credential_without_type())]
    #[should_panic(expected = "Credential(s) does not contain required \"vct_values\"")]
    #[case::mismatched_credential_type(dcql_and_credential_type_mismatch())]
    #[should_panic(expected = "Credential query validation error, query id = pid2")]
    #[case::not_enough_credential_for_claims_set(dcql_and_credential_with_mismatched_claim_sets())]
    #[should_panic(
        expected = "Credential sets validation error, credential set-option = another_credential: Credential(s) for credential-query with id = another_credential not found"
    )]
    #[case::credential_sets_mismatch(dcql_with_credential_sets_mismatch())]
    #[tokio::test]
    async fn validate_claims_failure(#[case] test_case: (DCQL, HashMap<String, Vec<Claim>>)) {
        let (dcql, credentials) = test_case;
        validate_credentials(&dcql, &credentials).unwrap();
    }

    fn dcql_with_claims() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"id": "b", "path": ["postal_code"], "values": ["90210", "90211"]},
                        {"id": "d", "path": ["region", 0, "street"]},
                        {"id": "e", "path": ["date_of_birth", null, "day"]}
                    ]
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "postal_code": "90210",
                    "vct": "https://credentials.example.com/identity_credential",
                    "region": [
                        {
                            "street": "1"
                        }
                    ],
                    "date_of_birth": [
                        {
                            "day": 1
                        }
                    ]
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcql_with_claim_sets() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"id": "b", "path": ["postal_code"], "values": ["90210", "90211"]},
                        {"id": "d", "path": ["region", 0, "street"]},
                        {"id": "e", "path": ["date_of_birth", null, "day"], "values": [2]}
                    ],
                    "claim_sets": [
                        ["b", "d"],
                        ["d", "e"]
                    ]
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "postal_code": "90210",
                    "vct": "https://credentials.example.com/identity_credential",
                    "region": [
                        {
                            "street": "1"
                        }
                    ],
                    "date_of_birth": [
                        {
                            "day": 1
                        }
                    ]
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcql_and_credential_with_mismatched_claim_sets() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"id": "b", "path": ["postal_code"], "values": ["90210", "90211"]},
                        {"id": "d", "path": ["region", 0, "street"]},
                        {"id": "e", "path": ["date_of_birth", null, "day"], "values": [2]}
                    ],
                    "claim_sets": [
                        ["b", "d"],
                        ["d", "e"]
                    ]
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "vct": "https://credentials.example.com/identity_credential",
                    "postal_code": "77777",
                    "region": [
                        {
                            "street": "1"
                        }
                    ],
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcql_and_ldp_vc_credential() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "ldp_vc",
                    "meta": {
                        "type_values": [["VerifiableCredential", "PermanentResident"]]
                    },
                    "claims": [
                        {"path": ["credentialSubject", "givenName"]}
                    ]
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "type": ["VerifiableCredential", "PermanentResident"],
                    "credentialSubject": {
                        "givenName": "John"
                    }
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcql_and_credential_with_mismatched_query_id() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["postal_code"], "values": ["90210"]}
                    ]
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "vct": "https://credentials.example.com/identity_credential",
                    "postal_code": "90211"
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcql_and_credential_with_mismatched_values() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["postal_code"], "values": ["90210"]}
                    ]
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "vct": "https://credentials.example.com/identity_credential",
                    "postal_code": "90211"
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcq_and_credential_with_missing_claims() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["missing_field"]}
                    ]
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "vct": "https://credentials.example.com/identity_credential",
                    "some_field": "value"
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcql_with_invalid_path() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["field", "invalid[path"]}
                    ]
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                   "vct": "https://credentials.example.com/identity_credential",
                    "field": {
                        "value": "test"
                    }
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcql_and_credential_without_type() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "some_field": "value"
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcql_and_credential_type_mismatch() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/new_identity_credential"]
                    },
                }
        ))
        .unwrap();

        let dcql = DCQL::new(vec![dcql_credential].try_into().unwrap());
        let mut credentials = HashMap::new();
        let claims: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "vct": "https://credentials.example.com/identity_credential"
                }
            ]
        ))
        .unwrap();
        credentials.insert("pid2".to_string(), claims);
        (dcql, credentials)
    }

    fn dcql_with_credential_sets() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let dcql_credential1: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid1",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["postal_code"], "values": ["90210"]}
                    ]
                }
        ))
        .unwrap();

        let dcql_credential2: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid2",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["family_name"], "values": ["Doe"]}
                    ]
                }
        ))
        .unwrap();

        let dcql_credential3: DCQLCredential = serde_json::from_value(json!(
                {
                    "id": "pid3",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [
                        {"path": ["age"], "values": [18]}
                    ]
                }
        ))
        .unwrap();

        let credential_set = serde_json::from_value::<DcqlCredentialSet>(json!(
            {
                "purpose": "Identification",
                "options": [
                    ["pid1", "pid3"],
                    ["pid2", "pid3"]
                ]
            }
        ))
        .unwrap();

        let optional_set = serde_json::from_value::<DcqlCredentialSet>(json!(
            {
              "required": false,
              "options": [
                [ "nice_to_have_credential" ]
              ]
            }
        ))
        .unwrap();

        let mut dcql = DCQL::new(
            vec![dcql_credential1, dcql_credential2, dcql_credential3]
                .try_into()
                .unwrap(),
        );
        dcql = dcql
            .add_credential_set(credential_set)
            .add_credential_set(optional_set);

        let mut credentials = HashMap::new();
        let claims1: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "vct": "https://credentials.example.com/identity_credential",
                    "postal_code": "7777"
                }
            ]
        ))
        .unwrap();
        let claims2: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "vct": "https://credentials.example.com/identity_credential",
                    "family_name": "Doe"
                }
            ]
        ))
        .unwrap();
        let claims3: Vec<Claim> = serde_json::from_value(json!(
            [
                {
                    "vct": "https://credentials.example.com/identity_credential",
                    "age": 18
                }
            ]
        ))
        .unwrap();

        credentials.insert("pid1".to_string(), claims1);
        credentials.insert("pid2".to_string(), claims2);
        credentials.insert("pid3".to_string(), claims3);
        (dcql, credentials)
    }

    fn dcql_with_credential_sets_mismatch() -> (DCQL, HashMap<String, Vec<Claim>>) {
        let (mut dcql, claims) = dcql_with_credential_sets();
        let new_set = serde_json::from_value::<DcqlCredentialSet>(json!(
            {
              "options": [
                [ "another_credential" ]
              ]
            }
        ))
        .unwrap();
        dcql = dcql.add_credential_set(new_set);

        (dcql, claims)
    }

    fn sample_sdjwt_presentation_for_dcql() -> (Value, Value) {
        let presentation_for_dcql = json!(
        {"id":["eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVwbmhBQXI5Tk51TnJ6M1pydU5ibTY0NGk5aW9VYW1xSHBZQXBTNldSUVNlTiN6RG5hZXBuaEFBcjlOTnVOcnozWnJ1TmJtNjQ0aTlpb1VhbXFIcFlBcFM2V1JRU2VOIn0.eyJfc2QiOlsiTWdsdFNpQUczcUpCTWMyUXU0UnVDUk1RSl9PNzdBZTI5ak9MY0NtRFNLUSIsImhfRkFmTEdCeVVyWHo5dkRNRHN1QnZzd2k3UDBRdlRhT0dyTW5XbTlDbEkiLCJsUzJVaWhBeU1ieEZ1cUJrS1ZhTmJDbmE1UjA5U1dQcGpVOFc4eDliakNnIl0sImlhdCI6MTc0NzI2ODYxMywiZGF0ZSI6IjA5LzA5LzE5ODkiLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlc2tNWUozUmNrdkUxeXJ4cE1mTmtXTkxBdnptVXhFQjJKb3o3ZlF4OHRMQXUiLCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWVwbmhBQXI5Tk51TnJ6M1pydU5ibTY0NGk5aW9VYW1xSHBZQXBTNldSUVNlTiIsImV4cCI6MTc3ODgwNDYxMywibmJmIjoxNzQ3MjY4NjEzLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibGVGdmtuNFlKNGtUdE45MUVQZmU4ZlRuN1hQWm5kMUtQV0Yxd193cDhYSSIsInkiOiJUZ0lwNjlfV3oxODFCYlZMcHg5cE16SW5fQ0JWeGhMbXRvcUFueE90ZDIwIn19fQ.P4e1UwBcxKMFSPq3xm9fFLUn8gJI6LdUQVUD1eIQLZLakMja7af-blESspA2RYS0vJ3NrNqUgft3RZ2v5dKlEw~WyJIc3RSS2JWR3JmVkViMk5lYTBwT0JRIiwgIm5hbWUiLCAiSm9obiJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiT2dtazBIUlJPR1N5bDZaOWd1dTdydTFYOHR5VnZ1R0tsTXpkNkwwNUVubyIsIm5vbmNlIjoiN2dMaFFpdC1vY2FvMVNQejFKbWhyYm1GenNCelluak54ZVVnUHFWaWpzbyIsImlhdCI6MTc0NzI2ODYxMywiYXVkIjoiZGlkOmtleTp6RG5hZWdFYjRScWppR3ZHZ0xpWXFqYm05ckFjZzZ4ZmJHUG5MOXBrZnhma0F1M3ZrIn0.eauedo3Oz9aluDNN_xweJtDjXRjwyfKxqAmZjBARBWEvy6J09HhrrBHmS7Yr7LGG9FE27OXziV90ovnUv3M9sw"]}
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
            {"id":[{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"holder":"did:key:zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ","verifiableCredential":{"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/citizenship/v1"],"type":["VerifiableCredential","PermanentResident"],"credentialSubject":{"givenName":"John","type":["PermanentResident","Person"],"birthDate":"09/09/1989","familyName":"Doe","id":"did:key:zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ"},"issuer":"did:key:zDnaeryTefzWK446XPbJwNkLyXiLhPcEnkfxYVyRbS8Vk6U8r","issuanceDate":"2025-05-15T06:22:50.399115247Z","expirationDate":"2030-05-14T06:22:50.399115247Z","proof":{"type":"EcdsaSecp256r1Signature2019","created":"2025-05-15T06:22:50.399Z","verificationMethod":"did:key:zDnaeryTefzWK446XPbJwNkLyXiLhPcEnkfxYVyRbS8Vk6U8r#zDnaeryTefzWK446XPbJwNkLyXiLhPcEnkfxYVyRbS8Vk6U8r","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..2WBzR1pbcRqzt2YJ-B9Kts663M_8jtNi8inUTOPloPpNqMufiNY83MLE-dx_m4g6OXddXgrsJIziOHCAiH3bXA"}},"proof":{"type":"EcdsaSecp256r1Signature2019","created":"2025-05-15T06:22:50.421Z","verificationMethod":"did:key:zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ#zDnaeW2x7yezzYRvcjJbsiDfc73rCVEK69Hgo9gf6KKBvm3QZ","proofPurpose":"assertionMethod","nonce":"7CbUWaXwH5z14AYNj8FZjvfRZvHIf5o8fi-3XshrlwU","jws":"eyJhbGciOiJFUzI1NiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..rPb9wUX15ByHLEGjcl5oYpH0EzOkGGYHrBm22OERyqvTBD-akjAHO-HUB7W6gcd_fAhbmnCL8A0L36RVir5LXg"}}]}
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

    async fn get_id_to_cred_map() -> HashMap<String, Vec<CredentialEntry>> {
        let ids = ["1", "2", "3", "4", "5"];
        let cred_entries: Vec<CredentialEntry> = get_credential_entries().await;
        let mut map = HashMap::new();
        for (index, &id) in ids.iter().enumerate() {
            map.insert(id.to_string(), vec![cred_entries[index].clone()]);
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
