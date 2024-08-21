use serde_json::Value as Json;

pub fn find_json_element<'a>(json: &'a Json, json_path: &str) -> Option<&'a Json> {
    if json_path == "$" {
        return Some(json);
    }

    let mut current = json;

    let path = json_path.strip_prefix("$.").unwrap_or(json_path);
    let parts = path.split('.');

    for part in parts {
        if let Some((key, array_index)) = part.split_once('[') {
            current = current.get(key)?;

            if let Some(index) = array_index.strip_suffix(']') {
                if let Ok(index) = index.parse::<usize>() {
                    current = current.get(index)?;
                } else {
                    return None;
                }
            } else {
                return None;
            }
        } else {
            current = current.get(part)?;
        }
    }

    Some(current)
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::utils::json::find_json_element;

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
            find_json_element(&json_data, "$.address.street"),
            Some(&json_data["address"]["street"])
        );
        assert_eq!(
            find_json_element(&json_data, "$.address.city"),
            Some(&json_data["address"]["city"])
        );
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
}
