use crate::nonce::NonceData;
use crate::vc::claims::{Claim, Claims};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

impl Serialize for NonceData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("NonceData", 3)?;
        let unix_timestamp = self.created.unix_timestamp();
        let seconds = self.expires_in.map(|d| d.whole_seconds());

        state.serialize_field("value", &self.value)?;
        state.serialize_field("created", &unix_timestamp)?;
        state.serialize_field("expires_in", &seconds)?;
        state.end()
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
    use crate::nonce::{Nonce, NonceData};
    use crate::utils::serde::Helpers;
    use crate::vc::claims::{Claim, Claims};
    use time::{Duration, OffsetDateTime};

    #[test]
    fn put_str_works_correctly() {
        let mut claims = Claims::new();
        claims.put_str("key", "value");

        assert_eq!(
            claims.get("key").unwrap(),
            &Claim::String("value".to_string())
        );
    }

    #[test]
    fn put_dt_works_correctly() {
        let mut claims = Claims::new();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let dt = OffsetDateTime::from_unix_timestamp(now).unwrap();
        claims.put_dt("key", dt);

        assert_eq!(claims.get("key").unwrap(), &Claim::Int(now));
    }

    #[test]
    fn serialization_of_nonce_data_works_correctly() {
        let nonce_offset_date_time = OffsetDateTime::from_unix_timestamp(1727962239).unwrap();
        let nonce_data = NonceData {
            value: Nonce::from_secret("nOnCe".to_owned()),
            created: nonce_offset_date_time,
            expires_in: Some(Duration::seconds(86440)),
        };

        let expected = r#"{"value":"nOnCe","created":1727962239,"expires_in":86440}"#;
        let nonce_to_check = serde_json::to_string(&nonce_data).unwrap();

        assert_eq!(expected, nonce_to_check)
    }
}
