//! Credential Claims module

use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snafu::Snafu;
use std::collections::HashMap;
use std::convert::{From, TryFrom};
use strum::Display;
use tracing::{instrument, Level};
use zeroize::Zeroize;

#[derive(Snafu, DebugError)]
pub enum Error {
    #[snafu(display("Json value is not a Value::Object"))]
    NotObject,

    #[snafu(display("Float value can not be converted to Value::Number"))]
    Float,
}

/// Credential Claims
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Claims {
    #[serde(flatten)]
    claims: HashMap<String, Claim>,
}

impl Claims {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new() -> Self {
        Self {
            claims: HashMap::new(),
        }
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn claims(&self) -> &HashMap<String, Claim> {
        &self.claims
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn get(&self, key: &str) -> Option<&Claim> {
        self.claims.get(key)
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn insert(&mut self, key: String, claim: Claim) {
        self.claims.insert(key, claim);
    }
}

impl TryFrom<Value> for Claims {
    type Error = Error;

    #[instrument(level = Level::TRACE, err(), ret())]
    fn try_from(value: Value) -> Result<Self, Error> {
        match value {
            Value::Object(map) => Ok(Self {
                claims: json_value_to_map(map),
            }),
            _ => NotObjectSnafu.fail(),
        }
    }
}

impl TryFrom<Claims> for Value {
    type Error = Error;

    #[instrument(level = Level::TRACE, err(), ret())]
    fn try_from(value: Claims) -> Result<Self, Error> {
        claims_object_to_json_value(&value.claims)
    }
}

impl From<Claims> for Claim {
    #[instrument(level = Level::TRACE, ret())]
    fn from(value: Claims) -> Self {
        Self::Object(value.claims)
    }
}

#[derive(Serialize, Deserialize, Debug, Display, Clone, PartialEq)]
#[serde(untagged)]
pub enum Claim {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    String(String),
    Array(Vec<Claim>),
    Object(HashMap<String, Claim>),
}

impl Claim {
    #[instrument(level = Level::TRACE, ret())]
    pub fn as_int(&self) -> Option<&i64> {
        match self {
            Self::Int(int_val) => Some(int_val),
            _ => None,
        }
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(claim_str) => Some(claim_str),
            _ => None,
        }
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn get(&self, key: &str) -> Option<&Claim> {
        if let Self::Object(map) = self {
            return map.get(key);
        }

        None
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn as_object(&self) -> Option<&HashMap<String, Claim>> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }
}

impl TryFrom<Claim> for Value {
    type Error = Error;

    #[instrument(level = Level::TRACE, err(), ret())]
    fn try_from(value: Claim) -> Result<Self, Error> {
        match value {
            Claim::Null => Ok(Self::Null),
            Claim::Bool(val) => Ok(Self::Bool(val)),
            Claim::Int(val) => Ok(Self::Number(val.into())),
            Claim::UInt(val) => Ok(Self::Number(val.into())),
            Claim::Float(val) => f64_to_value(val),
            Claim::String(ref val) => Ok(Self::String(val.clone())),
            Claim::Array(ref arr) => arr_to_value(arr),
            Claim::Object(ref map) => claims_object_to_json_value(map),
        }
    }
}

impl From<Value> for Claim {
    #[instrument(level = Level::TRACE, ret())]
    fn from(value: Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(val) => Self::Bool(val),
            Value::Number(val) => json_number_to_claims(val),
            Value::String(val) => Self::String(val),
            Value::Array(arr) => Self::Array(arr.into_iter().map(|val| val.into()).collect()),
            Value::Object(map) => Self::Object(json_value_to_map(map)),
        }
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        erase_claim(self);
    }
}

#[instrument(level = Level::TRACE, ret())]
fn erase_claim(claim: &mut Claim) {
    match claim {
        Claim::Null => {}
        Claim::Bool(val) => val.zeroize(),
        Claim::Int(val) => val.zeroize(),
        Claim::UInt(val) => val.zeroize(),
        Claim::Float(val) => val.zeroize(),
        Claim::String(val) => val.zeroize(),
        Claim::Array(arr) => erase_array(arr),
        Claim::Object(map) => erase_map(map),
    }
}

#[instrument(level = Level::TRACE, ret())]
fn erase_array(array: &mut [Claim]) {
    array.iter_mut().for_each(erase_claim);
}

#[instrument(level = Level::TRACE, ret())]
fn erase_map(map: &mut HashMap<String, Claim>) {
    map.values_mut().for_each(erase_claim);
}

#[instrument(level = Level::TRACE, err(), ret())]
fn f64_to_value(val: f64) -> Result<Value, Error> {
    let number = serde_json::Number::from_f64(val).ok_or_else(|| FloatSnafu.build())?;

    Ok(Value::Number(number))
}

#[instrument(level = Level::TRACE, err(), ret())]
fn arr_to_value(arr: &[Claim]) -> Result<Value, Error> {
    let mut values: Vec<Value> = vec![];

    for claim in arr {
        values.push(claim.clone().try_into()?);
    }

    Ok(Value::Array(values))
}

#[instrument(level = Level::TRACE, ret())]
fn json_number_to_claims(val: serde_json::Number) -> Claim {
    if let Some(int_val) = val.as_i64() {
        return Claim::Int(int_val);
    }

    if let Some(uint_val) = val.as_u64() {
        return Claim::UInt(uint_val);
    }

    Claim::Float(
        val.as_f64()
            .unwrap_or_else(|| panic!("unexpected type of json Number value: {:?}", val)),
    )
}

#[instrument(level = Level::TRACE, ret())]
fn json_value_to_map(val: serde_json::Map<String, Value>) -> HashMap<String, Claim> {
    let mut claims_map: HashMap<String, Claim> = HashMap::new();

    for (k, v) in val.into_iter() {
        claims_map.insert(k, v.into());
    }

    claims_map
}

#[instrument(level = Level::TRACE, err(), ret())]
fn claims_object_to_json_value(map: &HashMap<String, Claim>) -> Result<Value, Error> {
    let mut json_map: serde_json::Map<String, Value> = serde_json::Map::new();

    for (k, v) in map {
        json_map.insert(k.clone(), v.clone().try_into()?);
    }

    Ok(Value::Object(json_map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::f64;
    use rstest::rstest;
    use serde_json::json;

    #[tokio::test]
    async fn claims_get_returns_existing_claim() {
        let claims: Claims = json!({
            "key": "test_value"
        })
        .try_into()
        .unwrap();

        assert_eq!(
            claims.get("key").unwrap(),
            &Claim::String("test_value".to_string())
        );
    }

    #[tokio::test]
    async fn claims_get_returns_none_if_the_key_does_not_exist() {
        let claims: Claims = json!({
            "key": "test_value"
        })
        .try_into()
        .unwrap();

        assert!(claims.get("invalid_key").is_none());
    }

    #[tokio::test]
    async fn claims_insert_works_correctly() {
        let expected_claims = json!({
            "key": "test_value"
        })
        .try_into()
        .unwrap();

        let mut claims = Claims::new();

        claims.insert("key".to_string(), Claim::String("test_value".to_string()));

        assert_eq!(claims, expected_claims);
    }

    #[rstest]
    #[case((json!(null), Claim::Null))]
    #[case((json!(true), Claim::Bool(true)))]
    #[case((json!(-12345), Claim::Int(-12345)))]
    #[case((json!(u64::MAX), Claim::UInt(u64::MAX)))]
    #[case((json!(123.45), Claim::Float(123.45)))]
    #[case((json!("test_value"), Claim::String("test_value".to_string())))]
    #[case((json!([]), Claim::Array(vec![])))]
    #[case((json!([123, "test"]), Claim::Array(vec![Claim::Int(123), Claim::String("test".to_string())])))]
    #[case((json!({}), Claim::Object(HashMap::new())))]
    #[case(nested_objects_case())]
    #[tokio::test]
    async fn convertaion_json_value_to_claim_works_correctly(#[case] test_case: (Value, Claim)) {
        let (json_value, expected_claim) = test_case;
        let claim: Claim = json_value.into();
        assert_eq!(claim, expected_claim);
    }

    #[rstest]
    #[case((json!(null), Claim::Null))]
    #[case((json!(true), Claim::Bool(true)))]
    #[case((json!(-12345), Claim::Int(-12345)))]
    #[case((json!(u64::MAX), Claim::UInt(u64::MAX)))]
    #[case((json!(123.45), Claim::Float(123.45)))]
    #[case((json!("test_value"), Claim::String("test_value".to_string())))]
    #[case((json!([]), Claim::Array(vec![])))]
    #[case((json!([123, "test"]), Claim::Array(vec![Claim::Int(123), Claim::String("test".to_string())])))]
    #[case((json!({}), Claim::Object(HashMap::new())))]
    #[case(nested_objects_case())]
    #[tokio::test]
    async fn convertaion_claim_to_json_value_works_correctly(#[case] test_case: (Value, Claim)) {
        let (expected_json_value, claim) = test_case;
        let json_value: Value = claim.try_into().unwrap();
        assert_eq!(json_value, expected_json_value);
    }

    #[rstest]
    #[case(Claim::Float(f64::NAN))]
    #[case(Claim::Float(f64::INFINITY))]
    #[case(Claim::Float(f64::NEG_INFINITY))]
    #[tokio::test]
    #[should_panic(expected = "Float value can not be converted to Value::Number")]
    async fn convertaion_claim_to_json_fails_when_float_is_not_finite(#[case] claim: Claim) {
        let json_value: Value = claim.try_into().unwrap();
    }

    #[tokio::test]
    async fn convertaion_json_value_to_claims_works_correctly() {
        let json_value = json!({
            "key_null": null,
            "key_bool": true,
            "key_int": -12345,
            "key_uint": u64::MAX,
            "key_float": 123.45,
            "key_string": "test_value",
            "key_array": [],
            "key_object": {},
        });

        let claims: Claims = json_value.try_into().unwrap();

        assert_eq!(claims.get("key_null").unwrap(), &Claim::Null);
        assert_eq!(claims.get("key_bool").unwrap(), &Claim::Bool(true));
        assert_eq!(claims.get("key_int").unwrap(), &Claim::Int(-12345));
        assert_eq!(claims.get("key_uint").unwrap(), &Claim::UInt(u64::MAX));
        assert_eq!(claims.get("key_float").unwrap(), &Claim::Float(123.45));
        assert_eq!(
            claims.get("key_string").unwrap(),
            &Claim::String("test_value".to_string())
        );
        assert_eq!(claims.get("key_array").unwrap(), &Claim::Array(vec![]));
        assert_eq!(
            claims.get("key_object").unwrap(),
            &Claim::Object(HashMap::new())
        );
    }

    #[tokio::test]
    #[should_panic(expected = "Json value is not a Value::Object")]
    async fn convertaion_json_value_to_claims_fails_when_json_is_not_an_object() {
        let json_value = json!("test");
        let claims: Claims = json_value.try_into().unwrap();
    }

    #[tokio::test]
    async fn convertaion_claims_to_json_value_works_correctly() {
        let mut claims = Claims::new();

        claims.insert("key_null".to_string(), Claim::Null);
        claims.insert("key_bool".to_string(), Claim::Bool(true));
        claims.insert("key_int".to_string(), Claim::Int(-12345));
        claims.insert("key_uint".to_string(), Claim::UInt(u64::MAX));
        claims.insert("key_float".to_string(), Claim::Float(123.45));
        claims.insert(
            "key_string".to_string(),
            Claim::String("test_value".to_string()),
        );
        claims.insert("key_array".to_string(), Claim::Array(vec![]));
        claims.insert("key_object".to_string(), Claim::Object(HashMap::new()));

        let expected_json_value = json!({
            "key_null": null,
            "key_bool": true,
            "key_int": -12345,
            "key_uint": u64::MAX,
            "key_float": 123.45,
            "key_string": "test_value",
            "key_array": [],
            "key_object": {},
        });

        let json_value: Value = claims.try_into().unwrap();

        assert_eq!(json_value, expected_json_value);
    }

    fn nested_objects_case() -> (Value, Claim) {
        let json_value = json!({ "key0": 123, "key1": { "key10": 456 }    });

        let mut internal_map = HashMap::new();
        internal_map.insert("key10".to_string(), Claim::Int(456));

        let mut map = HashMap::new();
        map.insert("key0".to_string(), Claim::Int(123));
        map.insert("key1".to_string(), Claim::Object(internal_map));

        (json_value, Claim::Object(map))
    }
}
