use serde_json::{Number, Value};
use time::OffsetDateTime;

pub trait Helpers {
    fn put_str<S: ToString>(&mut self, k: &str, v: S);

    fn put_dt(&mut self, k: &str, v: OffsetDateTime);
}

impl Helpers for serde_json::Map<String, Value> {
    fn put_str<S: ToString>(&mut self, k: &str, v: S) {
        self.insert(k.to_string(), Value::String(v.to_string()));
    }

    fn put_dt(&mut self, k: &str, v: OffsetDateTime) {
        let ts = v.unix_timestamp();
        self.insert(k.to_string(), Value::Number(Number::from(ts)));
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::serde::Helpers;
    use serde_json::{Map, Value};
    use time::OffsetDateTime;

    #[test]
    fn put_str_works_correctly() {
        let mut map = Map::new();
        map.put_str("key", "value");

        assert_eq!(map["key"], "value");
    }

    #[test]
    fn put_dt_works_correctly() {
        let mut map = Map::new();

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let dt = OffsetDateTime::from_unix_timestamp(now).unwrap();
        map.put_dt("key", dt);

        assert_eq!(map["key"], Value::Number(now.into()));
    }
}
