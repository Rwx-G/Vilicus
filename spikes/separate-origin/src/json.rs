//! The few JSON documents the control endpoints return, written by hand: a string escaper and a
//! flat object builder are all the spike needs.

/// Escapes `value` as a JSON string literal, quotes included.
pub fn string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A flat JSON object of string, number and boolean members.
#[derive(Default)]
pub struct Object {
    members: Vec<String>,
}

impl Object {
    /// Adds a string member.
    pub fn str(mut self, key: &str, value: &str) -> Self {
        self.members
            .push(format!("{}:{}", string(key), string(value)));
        self
    }

    /// Adds a number member.
    pub fn num(mut self, key: &str, value: u64) -> Self {
        self.members.push(format!("{}:{value}", string(key)));
        self
    }

    /// Adds a boolean member.
    pub fn bool(mut self, key: &str, value: bool) -> Self {
        self.members.push(format!("{}:{value}", string(key)));
        self
    }

    /// The object's text.
    pub fn finish(self) -> String {
        format!("{{{}}}", self.members.join(","))
    }
}

/// A JSON array of already serialised values.
pub fn array(values: &[String]) -> String {
    format!("[{}]", values.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        assert_eq!(string("a\"b\\c\n\u{1}"), r#""a\"b\\c\n\u0001""#);
    }

    #[test]
    fn objects_and_arrays_are_built() {
        let object = Object::default()
            .str("s", "x")
            .num("n", 3)
            .bool("b", true)
            .finish();
        assert_eq!(object, r#"{"s":"x","n":3,"b":true}"#);
        assert_eq!(array(&[object.clone(), object]).matches('{').count(), 2);
    }
}
