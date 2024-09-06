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
