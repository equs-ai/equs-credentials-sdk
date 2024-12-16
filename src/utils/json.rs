use crate::vc::claims::{Claim, Claims};
use common_macros::DebugError;
use serde_json::{json, Value as Json, Value};
use snafu::{Location, Snafu};
use std::fmt::Debug;
use tracing::{instrument, Level};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Parsing error: {details}"))]
    Parsing {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

#[instrument(
    level = Level::TRACE,
    skip(json),
    ret(),
)]
pub fn find_json_element<'a>(json: &'a Json, json_path: &str) -> Option<&'a Json> {
    if json_path == "$" {
        return Some(json);
    }

    let mut current = json;
    let path = json_path.trim_start_matches('$').trim_start_matches('.');
    let parts = path.split('.');

    for part in parts {
        if let Some((key_part, array_part)) = part.split_once('[') {
            // Handle keys with index bracket
            if !key_part.is_empty() {
                current = current.get(key_part)?;
            }

            if let Some(index_str) = array_part.strip_suffix(']') {
                if let Ok(index) = index_str.parse::<usize>() {
                    current = current.get(index)?;
                } else {
                    current = current.get(index_str.replace('\'', ""))?;
                }
            } else {
                return None;
            }
        } else {
            // Handle simple keys
            current = current.get(part)?;
        }
    }

    Some(current)
}

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn paths_to_json(paths: Vec<(&str, Value)>) -> Result<Value> {
    let mut json = json!({});
    for (p, value) in paths {
        let path = p.replacen("$.", "", 1);
        path_to_json(path.clone(), &mut json, &value)?;
    }

    Ok(json)
}

fn path_to_json(path: String, mut json_obj: &mut Value, value: &Value) -> Result<()> {
    let parts: Vec<&str> = path.split('.').collect();

    for (i, part) in parts.iter().enumerate() {
        if part.contains('[') && part.contains(']') {
            path_to_json_helper(json_obj, part, parts.len(), i, value)?;
        } else if i == parts.len() - 1 {
            json_obj[part] = value.to_owned();
        } else {
            if json_obj.get(part).is_none() {
                json_obj[part] = json!({});
            }
            json_obj = &mut json_obj[part];
        }
    }

    Ok(())
}

fn path_to_json_helper(
    json_obj: &mut Value,
    part: &str,
    length: usize,
    parts_index: usize,
    value: &Value,
) -> Result<()> {
    let key = part.split('[').next().ok_or(
        ParsingSnafu {
            details: "cannot parse key of json-path",
        }
        .build(),
    )?;
    let index: usize = part
        .split('[')
        .nth(1)
        .and_then(|i| i.trim_end_matches(']').parse::<usize>().ok())
        .ok_or(
            ParsingSnafu {
                details: "cannot parse index of json-path",
            }
            .build(),
        )?;

    if json_obj.get(key).is_none() {
        json_obj[key] = json!(vec![Value::Null; index + 1]);
    }

    if let Value::Array(arr) = &mut json_obj[key] {
        if index >= arr.len() {
            arr.resize(index + 1, Value::Null);
        }
        if parts_index == length - 1 {
            json_obj[part] = value.to_owned()
        } else if arr[index].is_null() {
            arr[index] = json!({});
        }
    }

    Ok(())
}

// TODO: get rid of Claim -> String convertation since it is considered to be insecure
pub fn claims_to_json_path(claims: Claims) -> Vec<(String, String)> {
    let mut flatten = vec![];
    flatten_claims(&mut flatten, &claims.into(), "$");

    flatten
}

fn flatten_claims(flatten: &mut Vec<(String, String)>, root: &Claim, parent_key: &str) {
    match root {
        Claim::Object(obj) => {
            for (key, value) in obj {
                let key = format!("{parent_key}.{key}");
                flatten_claims(flatten, value, &key);
            }
        }
        Claim::Array(vec) => {
            for value in vec {
                let key = format!("{parent_key}[*]");
                flatten_claims(flatten, value, &key);
            }
        }
        Claim::String(val) => {
            flatten.push((parent_key.to_owned(), val.clone()));
        }
        _ => {
            flatten.push((parent_key.to_owned(), serde_json::to_string(&root).unwrap()));
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::utils::json::{claims_to_json_path, find_json_element};

    #[test]
    fn test_find_json_element_root() {
        let json_data = json!("root_string");

        assert_eq!(find_json_element(&json_data, "$"), Some(&json_data));
    }

    #[test]
    fn test_find_json_element_simple_path() {
        let json_data = json!({
            "name": "John",
            "age": 30,
            "city": "New York"
        });

        assert_eq!(
            find_json_element(&json_data, "$.name"),
            Some(&json_data["name"])
        );
        assert_eq!(
            find_json_element(&json_data, "$.age"),
            Some(&json_data["age"])
        );
        assert_eq!(
            find_json_element(&json_data, "$.city"),
            Some(&json_data["city"])
        );
    }

    #[test]
    fn test_find_json_element_nested_path() {
        let json_data = json!({
            "name": "John",
            "address": {
                "street": "123 Main St",
                "city": "New York"
            }
        });

        assert_eq!(
            find_json_element(&json_data, "$.address['street']"),
            Some(&json_data["address"]["street"])
        );
        assert_eq!(
            find_json_element(&json_data, "$.address.city"),
            Some(&json_data["address"]["city"])
        );
    }

    #[test]
    fn test_find_json_element_root_array_index() {
        let json_data = json!([
            {
                "name": "John",
                "age": 35
            },
            {
                "name": "Alice",
                "age": 5
            },
        ]);

        assert_eq!(find_json_element(&json_data, "$[0]"), Some(&json_data[0]));
        assert_eq!(find_json_element(&json_data, "$[1]"), Some(&json_data[1]));
    }

    #[test]
    fn test_find_json_element_array_index() {
        let json_data = json!({
            "name": "John",
            "children": [
                {
                    "name": "Alice",
                    "age": 5
                },
                {
                    "name": "Bob",
                    "age": 8
                }
            ]
        });

        assert_eq!(
            find_json_element(&json_data, "$.children[0].name"),
            Some(&json_data["children"][0]["name"])
        );
        assert_eq!(
            find_json_element(&json_data, "$.children[1].age"),
            Some(&json_data["children"][1]["age"])
        );
    }

    #[test]
    fn test_find_json_element_invalid_path() {
        let json_data = json!({
            "name": "John",
            "age": 30,
            "city": "New York"
        });

        assert_eq!(find_json_element(&json_data, "$.nonexistent"), None);
        assert_eq!(find_json_element(&json_data, "$['nonexistent']"), None);
        assert_eq!(find_json_element(&json_data, "$.age.invalid"), None);
        assert_eq!(find_json_element(&json_data, "$.city[0]"), None);
    }

    #[test]
    fn test_find_json_element_invalid_array_index() {
        let json_data = json!({
            "name": "John",
            "children": [
                {
                    "name": "Alice",
                    "age": 5
                }
            ]
        });

        assert_eq!(find_json_element(&json_data, "$.children[1]"), None);
        assert_eq!(find_json_element(&json_data, "$.children[-1]"), None);
        assert_eq!(find_json_element(&json_data, "$.children[abc]"), None);
    }

    #[test]
    fn test_claims_to_json_path() {
        let json = json!({
            "name": "John",
            "email":
            {
                "personal": "work@mail.com",
                "work": null,
                "verified": true,
            },
            "age": 28,
        })
        .try_into()
        .unwrap();

        let claims = claims_to_json_path(json);

        assert_eq!(claims.len(), 5);
        assert!(claims.contains(&("$.name".to_string(), "John".to_string())));
        assert!(claims.contains(&("$.email.personal".to_string(), "work@mail.com".to_string())));
        assert!(claims.contains(&("$.email.work".to_string(), "null".to_string())));
        assert!(claims.contains(&("$.email.verified".to_string(), "true".to_string())));
        assert!(claims.contains(&("$.age".to_string(), "28".to_string())));
    }
}
