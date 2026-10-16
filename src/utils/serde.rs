use crate::vc::claims::{Claim, Claims};
use serde::{Deserialize, Deserializer, Serializer};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

pub trait Helpers {
    fn put_str<S: ToString>(&mut self, k: &str, v: S);

    fn put_dt(&mut self, k: &str, v: OffsetDateTime);
}

impl Helpers for Claims {
    fn put_str<S: ToString>(&mut self, k: &str, v: S) {
        self.insert(k.to_string(), Claim::String(v.to_string()));
    }

    fn put_dt(&mut self, k: &str, v: OffsetDateTime) {
        self.insert(k.to_string(), Claim::Int(v.unix_timestamp()));
    }
}

pub(crate) fn int_to_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let int: i64 = Deserialize::deserialize(deserializer)?;

    Ok(Some(Duration::seconds(int)))
}

pub(crate) fn int_to_offset_date_time<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let int: i64 = Deserialize::deserialize(deserializer)?;
    let date = OffsetDateTime::from_unix_timestamp(int)
        .map_err(|e| serde::de::Error::custom(e.to_string()))?;

    Ok(date)
}

pub(crate) fn duration_to_int<S>(
    duration: &Option<Duration>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let seconds = duration.and_then(|d| Some(d.whole_seconds()));

    serializer.serialize_some(&seconds)
}

pub fn accumulate_claim_names(json_obj: &Value, parent_key: String, keys: &mut Vec<String>) {
    match json_obj {
        Value::Object(map) => {
            for (k, v) in map {
                let new_key = if parent_key.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", parent_key, k)
                };
                accumulate_claim_names(v, new_key.clone(), keys);
                keys.push(new_key);
            }
        }
        Value::Array(arr) => {
            for (index, value) in arr.iter().enumerate() {
                let new_key = format!("{}[{}]", parent_key, index);
                accumulate_claim_names(value, new_key.clone(), keys);
                keys.push(new_key);
            }
        }
        _ => {
            keys.push(parent_key);
        }
    }
}

pub fn get_time_based_claim(claims: &Claims, key: &str) -> Option<time::OffsetDateTime> {
    claims
        .get(key)
        .and_then(|v| v.as_int())
        .and_then(|v| time::OffsetDateTime::from_unix_timestamp(*v).ok())
}

#[cfg(test)]
mod tests {
    use crate::utils::serde::{
        Helpers, accumulate_claim_names, duration_to_int, get_time_based_claim, int_to_duration,
        int_to_offset_date_time,
    };
    use crate::vc::claims::{Claim, Claims};
    use rstest::rstest;
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use time::{Duration, OffsetDateTime};

    #[test]
    fn put_str_works_correctly() {
        let mut claims = Claims::new();
        claims.put_str("key", "value");

        assert_eq!(&claims["key"], &Claim::String("value".to_string()));
    }

    #[test]
    fn put_dt_works_correctly() {
        let mut claims = Claims::new();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let dt = OffsetDateTime::from_unix_timestamp(now).unwrap();
        claims.put_dt("key", dt);

        assert_eq!(&claims["key"], &Claim::Int(now));
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct DurationWrapper {
        #[serde(
            deserialize_with = "int_to_duration",
            serialize_with = "duration_to_int"
        )]
        d: Option<Duration>,
    }

    #[derive(Debug, Deserialize)]
    struct OdtWrapper {
        #[serde(deserialize_with = "int_to_offset_date_time")]
        t: OffsetDateTime,
    }

    #[rstest]
    #[case::positive(3600)]
    #[case::zero(0)]
    fn int_to_duration_parses_seconds(#[case] seconds: i64) {
        let wrapper: DurationWrapper = serde_json::from_value(json!({ "d": seconds })).unwrap();

        assert_eq!(wrapper.d, Some(Duration::seconds(seconds)));
    }

    #[test]
    fn int_to_offset_date_time_parses_valid_unix_timestamp() {
        let ts: i64 = 1_700_000_000;
        let wrapper: OdtWrapper = serde_json::from_value(json!({ "t": ts })).unwrap();

        assert_eq!(wrapper.t.unix_timestamp(), ts);
    }

    #[test]
    #[should_panic(expected = "timestamp was not in range")]
    fn int_to_offset_date_time_rejects_out_of_range_timestamp() {
        // Far outside the valid OffsetDateTime range; the custom deserializer
        // surfaces the inner time error message via serde::de::Error::custom.
        let _wrapper: OdtWrapper = serde_json::from_value(json!({ "t": i64::MAX })).unwrap();
    }

    #[rstest]
    #[case::some(DurationWrapper { d: Some(Duration::seconds(120)) }, json!({ "d": 120 }))]
    #[case::none(DurationWrapper { d: None }, json!({ "d": null }))]
    fn duration_to_int_serializes_option_duration(
        #[case] input: DurationWrapper,
        #[case] expected: Value,
    ) {
        let v = serde_json::to_value(&input).unwrap();

        assert_eq!(v, expected);
    }

    #[rstest]
    #[case::nested_object(
        String::new(),
        json!({ "a": { "b": 1 }, "c": 2 }),
        vec!["a.b", "a", "c"],
    )]
    #[case::array_with_indices(
        String::new(),
        json!({ "items": ["x", "y"] }),
        vec!["items[0]", "items[1]", "items"],
    )]
    fn accumulate_claim_names_collects_expected_paths(
        #[case] parent_key: String,
        #[case] input: Value,
        #[case] expected_substrings: Vec<&str>,
    ) {
        let mut keys = Vec::new();

        accumulate_claim_names(&input, parent_key, &mut keys);

        for expected in expected_substrings {
            assert!(
                keys.iter().any(|k| k == expected),
                "missing expected key '{expected}' in {keys:?}",
            );
        }
    }

    #[test]
    fn accumulate_claim_names_pushes_parent_key_for_scalar() {
        let scalar: Value = json!("just-a-string");
        let mut keys = Vec::new();

        accumulate_claim_names(&scalar, "leaf".to_string(), &mut keys);

        assert_eq!(keys, vec!["leaf".to_string()]);
    }

    #[test]
    fn get_time_based_claim_returns_some_for_int_claim() {
        let mut claims = Claims::new();
        let ts: i64 = 1_700_000_000;
        claims.insert("exp".to_string(), Claim::Int(ts));

        let dt = get_time_based_claim(&claims, "exp").unwrap();

        assert_eq!(dt.unix_timestamp(), ts);
    }

    #[test]
    fn get_time_based_claim_returns_none_for_missing_key() {
        let claims = Claims::new();

        assert!(get_time_based_claim(&claims, "exp").is_none());
    }
}
