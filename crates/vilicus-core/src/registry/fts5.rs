//! The arguments of an FTS5 table, read back from the `CREATE VIRTUAL TABLE` text SQLite keeps in
//! `sqlite_master`, so the registry can hold them to the allowlist of D127. The reader accepts
//! only the plain forms: anything it does not recognise is a refusal, never a guess.

/// One `CREATE VIRTUAL TABLE` statement, split into its module and its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VirtualTable {
    /// The module name, as written.
    pub(crate) module: String,
    /// The arguments that name a column, as written.
    pub(crate) columns: Vec<String>,
    /// The `key = value` arguments: the key in lowercase, the value unquoted.
    pub(crate) options: Vec<(String, String)>,
}

/// Why the text of a virtual table cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// It does not start with `CREATE VIRTUAL TABLE <name> USING <module>(`.
    Header,
    /// The argument list is not closed by the last character, or a quote is not closed.
    Unbalanced,
    /// An argument is neither a bare name nor `key = value` with a bare key and a bare or quoted
    /// value.
    Argument,
}

/// Reads `sql`, the text SQLite keeps for a virtual table.
pub(crate) fn parse(sql: &str) -> Result<VirtualTable, ParseError> {
    let rest = strip_keywords(
        sql.trim_start_matches(is_space),
        &["CREATE", "VIRTUAL", "TABLE"],
    )
    .ok_or(ParseError::Header)?;
    let (_, rest) = take_name(rest).ok_or(ParseError::Header)?;
    let rest = strip_keywords(rest, &["USING"]).ok_or(ParseError::Header)?;
    let module_len = rest
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .ok_or(ParseError::Header)?;
    let (module, rest) = rest.split_at(module_len);
    let arguments = rest
        .trim_start_matches(is_space)
        .strip_prefix('(')
        .ok_or(ParseError::Header)?
        .trim_end_matches(is_space)
        .strip_suffix(')')
        .ok_or(ParseError::Unbalanced)?;
    if module.is_empty() {
        return Err(ParseError::Header);
    }
    let mut table = VirtualTable {
        module: module.to_owned(),
        columns: Vec::new(),
        options: Vec::new(),
    };
    for argument in split_top_level(arguments, ',')? {
        let argument = argument.trim_matches(is_space);
        match split_top_level(argument, '=')?.as_slice() {
            [column] => table.columns.push((*column).to_owned()),
            [key, value] => {
                let key = key.trim_matches(is_space);
                if !is_bare(key) {
                    return Err(ParseError::Argument);
                }
                table.options.push((
                    key.to_ascii_lowercase(),
                    unquote(value.trim_matches(is_space))?,
                ));
            }
            _ => return Err(ParseError::Argument),
        }
    }
    Ok(table)
}

/// SQLite's white space, ASCII only: space, tab, line feed, form feed, carriage return. Rust's
/// `char::is_whitespace` would also take a no-break space, which SQLite reads as part of a word.
fn is_space(character: char) -> bool {
    character.is_ascii_whitespace()
}

/// `text` after the keywords, each matched ignoring ASCII case and followed by white space.
fn strip_keywords<'a>(mut text: &'a str, keywords: &[&str]) -> Option<&'a str> {
    for keyword in keywords {
        let head = text.get(..keyword.len())?;
        let rest = &text[keyword.len()..];
        if !head.eq_ignore_ascii_case(keyword) || !rest.starts_with(is_space) {
            return None;
        }
        text = rest.trim_start_matches(is_space);
    }
    Some(text)
}

/// The table name, bare or quoted, and the text after it and its white space.
fn take_name(text: &str) -> Option<(&str, &str)> {
    let end = match text.chars().next()? {
        quote @ ('"' | '`' | '\'') => text[1..].find(quote)? + 2,
        '[' => text.find(']')? + 1,
        _ => text.find(is_space)?,
    };
    let (name, rest) = text.split_at(end);
    rest.starts_with(is_space)
        .then(|| (name, rest.trim_start_matches(is_space)))
}

/// `text` split at each `separator` outside quotes and parentheses.
fn split_top_level(text: &str, separator: char) -> Result<Vec<&str>, ParseError> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0_usize;
    let mut quote = None;
    for (index, character) in text.char_indices() {
        match (quote, character) {
            (Some(open), _) if character == closing(open) => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"' | '`' | '[') => quote = Some(character),
            (None, '(') => depth += 1,
            (None, ')') => depth = depth.checked_sub(1).ok_or(ParseError::Unbalanced)?,
            (None, _) if character == separator && depth == 0 => {
                parts.push(&text[start..index]);
                start = index + character.len_utf8();
            }
            (None, _) => {}
        }
    }
    if quote.is_some() || depth != 0 {
        return Err(ParseError::Unbalanced);
    }
    parts.push(&text[start..]);
    Ok(parts)
}

const fn closing(open: char) -> char {
    match open {
        '[' => ']',
        other => other,
    }
}

/// A bare word: ASCII letters, digits and underscores only, and not empty.
fn is_bare(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// A value: a bare word as it is, or a string in single or double quotes with its doubled
/// quotes undone. A quote inside the value that is not doubled is refused.
fn unquote(value: &str) -> Result<String, ParseError> {
    if is_bare(value) {
        return Ok(value.to_owned());
    }
    for quote in ['\'', '"'] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            let doubled = [quote, quote].iter().collect::<String>();
            let single = quote.to_string();
            if inner.replace(&doubled, "").contains(quote) {
                return Err(ParseError::Argument);
            }
            return Ok(inner.replace(&doubled, &single));
        }
    }
    Err(ParseError::Argument)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn the_plain_forms_are_read() {
        let table =
            parse("CREATE VIRTUAL TABLE notes USING fts5(body, content='', tokenize='porter')")
                .expect("parse");
        assert_eq!(table.module, "fts5");
        assert_eq!(table.columns, ["body"]);
        assert_eq!(
            table.options,
            options(&[("content", ""), ("tokenize", "porter")])
        );

        let table = parse(
            "create virtual table \"items_search\"   using FTS5 ( label ,title,CONTENT = \"items\" , tokenize = trigram )",
        )
        .expect("parse");
        assert_eq!(table.module, "FTS5");
        assert_eq!(table.columns, ["label", "title"]);
        assert_eq!(
            table.options,
            options(&[("content", "items"), ("tokenize", "trigram")])
        );
    }

    /// Forms the registry must see as written, so it can refuse them: extra words, tokenizer
    /// arguments, prefixes and quoted values with doubled quotes.
    #[test]
    fn other_forms_are_kept_as_written_for_the_allowlist() {
        let table = parse(
            "CREATE VIRTUAL TABLE t USING fts5(body UNINDEXED, tokenize='porter unicode61', prefix='2 3', content='it''s')",
        )
        .expect("parse");
        assert_eq!(table.columns, ["body UNINDEXED"]);
        assert_eq!(
            table.options,
            options(&[
                ("tokenize", "porter unicode61"),
                ("prefix", "2 3"),
                ("content", "it's")
            ])
        );
        let table = parse(
            "CREATE VIRTUAL TABLE t USING fts5(body, tokenize = \"unicode61 remove_diacritics 2\")",
        )
        .expect("parse");
        assert_eq!(
            table.options,
            options(&[("tokenize", "unicode61 remove_diacritics 2")])
        );
    }

    #[test]
    fn only_ascii_white_space_separates_the_header() {
        assert_eq!(
            parse("CREATE VIRTUAL TABLE notes\u{a0}USING fts5(body)"),
            Err(ParseError::Header)
        );
        assert!(parse("CREATE\x0cVIRTUAL TABLE notes USING fts5(body)").is_ok());
    }

    #[test]
    fn unreadable_text_is_refused() {
        let cases = [
            ("CREATE TABLE notes (body TEXT)", ParseError::Header),
            ("CREATE VIRTUAL TABLE notes fts5(body)", ParseError::Header),
            (
                "CREATE VIRTUAL TABLE notes USING (body)",
                ParseError::Header,
            ),
            ("CREATE VIRTUAL TABLE notes USING fts5", ParseError::Header),
            (
                "CREATE VIRTUAL TABLE notes USING fts5(body",
                ParseError::Unbalanced,
            ),
            (
                "CREATE VIRTUAL TABLE notes USING fts5(body, content='x)",
                ParseError::Unbalanced,
            ),
            (
                "CREATE VIRTUAL TABLE notes USING fts5(body))",
                ParseError::Unbalanced,
            ),
            (
                "CREATE VIRTUAL TABLE notes USING fts5(content = 'a' = 'b')",
                ParseError::Argument,
            ),
            (
                "CREATE VIRTUAL TABLE notes USING fts5(content = 'a' || 'b')",
                ParseError::Argument,
            ),
            (
                "CREATE VIRTUAL TABLE notes USING fts5(content = 'a' 'b')",
                ParseError::Argument,
            ),
            (
                "CREATE VIRTUAL TABLE notes USING fts5(\"tok enize\" = porter)",
                ParseError::Argument,
            ),
        ];
        for (sql, error) in cases {
            assert_eq!(parse(sql), Err(error), "{sql}");
        }
    }
}
