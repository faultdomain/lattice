//! YAML parsing utilities using yaml-rust2
//!
//! Provides YAML parsing with conversion to serde_json::Value for typed deserialization.
//! Uses yaml-rust2 for parsing and serde_json for all serialization needs.

use serde_json::{Map, Number, Value};
use yaml_rust2::{Yaml, YamlLoader};

/// Error type for YAML parsing
#[derive(Debug, Clone)]
pub struct YamlError(String);

impl std::fmt::Display for YamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for YamlError {}

/// Parse a YAML string into a serde_json::Value.
///
/// For multi-document YAML, returns only the first document.
/// Returns `Value::Null` for empty input.
pub fn parse_yaml(input: &str) -> Result<Value, YamlError> {
    let docs = YamlLoader::load_from_str(input).map_err(|e| YamlError(e.to_string()))?;
    match docs.into_iter().next() {
        Some(doc) => yaml_to_json(doc),
        None => Ok(Value::Null),
    }
}

/// Parse a multi-document YAML string into a Vec of serde_json::Values.
///
/// Each YAML document separated by `---` becomes a separate Value.
pub fn parse_yaml_multi(input: &str) -> Result<Vec<Value>, YamlError> {
    let docs = YamlLoader::load_from_str(input).map_err(|e| YamlError(e.to_string()))?;
    docs.into_iter().map(yaml_to_json).collect()
}

/// Convert a yaml_rust2::Yaml value to serde_json::Value
fn yaml_to_json(yaml: Yaml) -> Result<Value, YamlError> {
    match yaml {
        Yaml::Null => Ok(Value::Null),
        Yaml::Boolean(b) => Ok(Value::Bool(b)),
        Yaml::Integer(i) => Ok(Value::Number(i.into())),
        Yaml::Real(s) => {
            let f: f64 = s
                .parse()
                .map_err(|e: std::num::ParseFloatError| YamlError(e.to_string()))?;
            Ok(Number::from_f64(f)
                .map(Value::Number)
                .unwrap_or(Value::Null))
        }
        Yaml::String(s) => Ok(Value::String(s)),
        Yaml::Array(arr) => arr
            .into_iter()
            .map(yaml_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Yaml::Hash(map) => map
            .into_iter()
            .map(|(k, v)| {
                let key = match k {
                    Yaml::String(s) => s,
                    Yaml::Integer(i) => i.to_string(),
                    Yaml::Real(r) => r,
                    Yaml::Boolean(b) => b.to_string(),
                    Yaml::Null => "null".to_string(),
                    _ => return Err(YamlError("unsupported YAML key type".to_string())),
                };
                yaml_to_json(v).map(|v| (key, v))
            })
            .collect::<Result<Map<String, Value>, _>>()
            .map(Value::Object),
        Yaml::Alias(_) => Err(YamlError("YAML aliases not supported".to_string())),
        Yaml::BadValue => Err(YamlError("bad YAML value".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yaml_simple() {
        let yaml = "name: test\nvalue: 42";
        let result = parse_yaml(yaml).unwrap();
        assert_eq!(result["name"], "test");
        assert_eq!(result["value"], 42);
    }

    #[test]
    fn test_parse_yaml_nested() {
        let yaml = r#"
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 3
"#;
        let result = parse_yaml(yaml).unwrap();
        assert_eq!(result["metadata"]["name"], "my-app");
        assert_eq!(result["metadata"]["namespace"], "default");
        assert_eq!(result["spec"]["replicas"], 3);
    }

    #[test]
    fn test_parse_yaml_array() {
        let yaml = r#"
items:
  - name: one
  - name: two
"#;
        let result = parse_yaml(yaml).unwrap();
        let items = result["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["name"], "one");
        assert_eq!(items[1]["name"], "two");
    }

    #[test]
    fn test_parse_yaml_multi_doc() {
        let yaml = r#"
name: first
---
name: second
---
name: third
"#;
        let results = parse_yaml_multi(yaml).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["name"], "first");
        assert_eq!(results[1]["name"], "second");
        assert_eq!(results[2]["name"], "third");
    }

    #[test]
    fn test_parse_yaml_empty() {
        let result = parse_yaml("").unwrap();
        assert_eq!(result, Value::Null);
    }

    #[test]
    fn test_parse_yaml_invalid() {
        let result = parse_yaml("not: valid: yaml: {{");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_yaml_boolean() {
        let yaml = "enabled: true\ndisabled: false";
        let result = parse_yaml(yaml).unwrap();
        assert_eq!(result["enabled"], true);
        assert_eq!(result["disabled"], false);
    }

    #[test]
    fn test_parse_yaml_null() {
        let yaml = "value: null";
        let result = parse_yaml(yaml).unwrap();
        assert!(result["value"].is_null());
    }

    #[test]
    fn test_parse_yaml_float() {
        let yaml = "value: 1.5";
        let result = parse_yaml(yaml).unwrap();
        let value = result["value"].as_f64().unwrap();
        assert!((value - 1.5).abs() < 0.0001);
    }

    #[test]
    fn test_parse_yaml_kubernetes_manifest() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
"#;
        let result = parse_yaml(yaml).unwrap();
        assert_eq!(result["apiVersion"], "apps/v1");
        assert_eq!(result["kind"], "Deployment");
        assert_eq!(result["metadata"]["name"], "my-app");
        assert_eq!(result["spec"]["replicas"], 3);
    }

    #[test]
    fn test_deserialize_to_typed() {
        use serde::Deserialize;

        #[derive(Deserialize, Debug, PartialEq)]
        struct Config {
            name: String,
            count: i32,
        }

        let yaml = "name: test\ncount: 42";
        let value = parse_yaml(yaml).unwrap();
        let config: Config = serde_json::from_value(value).unwrap();
        assert_eq!(
            config,
            Config {
                name: "test".to_string(),
                count: 42
            }
        );
    }
}
