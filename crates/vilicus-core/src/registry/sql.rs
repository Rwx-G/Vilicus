//! A tokenizer for the `CREATE` statements SQLite keeps in `sqlite_master`, following SQLite's
//! own rules (white space, both comment forms, string literals, the three identifier quotings),
//! so the registry can compare a statement with the one a declaration implies token by token:
//! any clause the declaration does not imply (`DEFAULT`, `CHECK`, `COLLATE`, `ON CONFLICT`,
//! `REFERENCES`, `UNIQUE`, `WITHOUT ROWID`) is a token the comparison does not expect.

/// One token of an SQL statement. Comments and white space are dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Token {
    /// A bare word: a keyword or an unquoted identifier, as written.
    Word(String),
    /// An identifier in double quotes, back quotes or brackets, unquoted.
    Quoted(String),
    /// A string literal in single quotes, unquoted.
    Str(String),
    /// A numeric literal, as written.
    Number(String),
    /// Any other character.
    Punct(char),
}

/// Why a statement cannot be tokenized: a quote or a bracket that is never closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unterminated;

/// SQLite's white space: space, tab, line feed, form feed and carriage return.
const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\x0c' | b'\r')
}

/// A character that may start an identifier: an ASCII letter, an underscore, or any byte of a
/// multi-byte UTF-8 character, as SQLite reads it.
const fn starts_word(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80
}

const fn continues_word(byte: u8) -> bool {
    starts_word(byte) || byte.is_ascii_digit() || byte == b'$'
}

/// The tokens of `sql`.
pub(crate) fn tokenize(sql: &str) -> Result<Vec<Token>, Unterminated> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if is_space(byte) {
            index += 1;
        } else if bytes[index..].starts_with(b"--") {
            index = bytes[index..]
                .iter()
                .position(|&byte| byte == b'\n')
                .map_or(bytes.len(), |end| index + end + 1);
        } else if bytes[index..].starts_with(b"/*") {
            index = sql[index + 2..]
                .find("*/")
                .map_or(bytes.len(), |end| index + 2 + end + 2);
        } else if let Some(close) = match byte {
            b'\'' | b'"' | b'`' => Some(byte),
            b'[' => Some(b']'),
            _ => None,
        } {
            let (text, end) = quoted(sql, index, close)?;
            tokens.push(match byte {
                b'\'' => Token::Str(text),
                _ => Token::Quoted(text),
            });
            index = end;
        } else if starts_word(byte) {
            let end = scan(bytes, index, continues_word);
            tokens.push(Token::Word(sql[index..end].to_owned()));
            index = end;
        } else if byte.is_ascii_digit()
            || (byte == b'.' && bytes.get(index + 1).is_some_and(u8::is_ascii_digit))
        {
            let end = scan(bytes, index, |byte| {
                byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_'
            });
            tokens.push(Token::Number(sql[index..end].to_owned()));
            index = end;
        } else {
            let character = sql[index..].chars().next().ok_or(Unterminated)?;
            tokens.push(Token::Punct(character));
            index += character.len_utf8();
        }
    }
    Ok(tokens)
}

fn scan(bytes: &[u8], start: usize, keep: impl Fn(u8) -> bool) -> usize {
    bytes[start..]
        .iter()
        .position(|&byte| !keep(byte))
        .map_or(bytes.len(), |end| start + end)
}

/// The text of the quoted token at `start`, its doubled closing quotes undone (none for
/// brackets), and the index after it.
fn quoted(sql: &str, start: usize, close: u8) -> Result<(String, usize), Unterminated> {
    let bytes = sql.as_bytes();
    let mut text = String::new();
    let mut from = start + 1;
    loop {
        let end = from
            + bytes[from..]
                .iter()
                .position(|&byte| byte == close)
                .ok_or(Unterminated)?;
        text.push_str(&sql[from..end]);
        if close != b']' && bytes.get(end + 1) == Some(&close) {
            text.push(char::from(close));
            from = end + 2;
        } else {
            return Ok((text, end + 1));
        }
    }
}

/// One token a declaration implies: a keyword, which only a bare word matches; a name, which a
/// bare word or a quoted identifier matches; or a punctuation character. Words and names compare
/// ignoring ASCII case, as SQLite does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expected<'a> {
    Keyword(&'a str),
    Name(&'a str),
    Punct(char),
}

impl Expected<'_> {
    fn matches(self, token: &Token) -> bool {
        match (self, token) {
            (Self::Keyword(keyword), Token::Word(word)) => keyword.eq_ignore_ascii_case(word),
            (Self::Name(name), Token::Word(word) | Token::Quoted(word)) => {
                name.eq_ignore_ascii_case(word)
            }
            (Self::Punct(expected), Token::Punct(found)) => expected == *found,
            _ => false,
        }
    }
}

/// True when `tokens` are exactly `expected`.
pub(crate) fn matches(expected: &[Expected<'_>], tokens: &[Token]) -> bool {
    expected.len() == tokens.len()
        && expected
            .iter()
            .zip(tokens)
            .all(|(expected, token)| expected.matches(token))
}

/// `expected` as SQL text, for an error message.
pub(crate) fn render(expected: &[Expected<'_>]) -> String {
    let mut text = String::new();
    for token in expected {
        match token {
            Expected::Keyword(word) | Expected::Name(word) => {
                if !text.is_empty() && !text.ends_with('(') {
                    text.push(' ');
                }
                text.push_str(word);
            }
            Expected::Punct(character) => text.push(*character),
        }
    }
    text
}

/// True when `found` and `template` hold the same tokens, words compared ignoring ASCII case and
/// everything else exactly: for statements SQLite writes itself, such as FTS5's shadow tables.
pub(crate) fn same_statement(template: &[Token], found: &[Token]) -> bool {
    template.len() == found.len()
        && template.iter().zip(found).all(|pair| match pair {
            (Token::Word(left), Token::Word(right)) => left.eq_ignore_ascii_case(right),
            (left, right) => left == right,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(text: &str) -> Token {
        Token::Word(text.to_owned())
    }

    #[test]
    fn statements_split_into_sqlite_tokens() {
        let tokens = tokenize(
            "CREATE TABLE \"my \"\"t\"\" \" ( [a b] `c``d` TEXT, -- a comment\n x INTEGER DEFAULT 'it''s' /* block */ CHECK (x > 1.5e3) ) ",
        )
        .expect("tokenize");
        assert_eq!(
            tokens,
            [
                word("CREATE"),
                word("TABLE"),
                Token::Quoted("my \"t\" ".to_owned()),
                Token::Punct('('),
                Token::Quoted("a b".to_owned()),
                Token::Quoted("c`d".to_owned()),
                word("TEXT"),
                Token::Punct(','),
                word("x"),
                word("INTEGER"),
                word("DEFAULT"),
                Token::Str("it's".to_owned()),
                word("CHECK"),
                Token::Punct('('),
                word("x"),
                Token::Punct('>'),
                Token::Number("1.5e3".to_owned()),
                Token::Punct(')'),
                Token::Punct(')'),
            ]
        );
    }

    /// A comment or a quote hides what it holds: the words inside are not tokens.
    #[test]
    fn comments_and_quotes_hide_their_content() {
        assert_eq!(
            tokenize("a /* b c */ d -- e f").expect("tokenize"),
            [word("a"), word("d")]
        );
        assert_eq!(
            tokenize("a 'NOT NULL' \"x\" /* unterminated").expect("tokenize"),
            [
                word("a"),
                Token::Str("NOT NULL".to_owned()),
                Token::Quoted("x".to_owned())
            ]
        );
    }

    #[test]
    fn an_unterminated_quote_is_refused() {
        for sql in ["a 'b", "a \"b", "a [b", "a `b", "a 'b''"] {
            assert_eq!(tokenize(sql), Err(Unterminated), "{sql}");
        }
    }

    /// SQLite's white space is ASCII only: a no-break space is part of a word, so it makes the
    /// statement differ rather than vanish.
    #[test]
    fn only_ascii_white_space_separates() {
        assert_eq!(tokenize("a\u{a0}b").expect("tokenize"), [word("a\u{a0}b")]);
        assert_eq!(
            tokenize("a\x0cb").expect("tokenize"),
            [word("a"), word("b")]
        );
    }

    #[test]
    fn keywords_match_bare_words_only_and_names_match_quoted_identifiers() {
        let expected = [Expected::Name("items"), Expected::Keyword("NOT")];
        assert!(matches(
            &expected,
            &tokenize("ITEMS not").expect("tokenize")
        ));
        assert!(matches(
            &expected,
            &tokenize("\"Items\" NOT").expect("tokenize")
        ));
        assert!(!matches(
            &expected,
            &tokenize("items \"NOT\"").expect("tokenize")
        ));
        assert!(!matches(
            &expected,
            &tokenize("'items' NOT").expect("tokenize")
        ));
        assert!(!matches(
            &expected,
            &tokenize("items NOT NULL").expect("tokenize")
        ));
        assert_eq!(render(&expected), "items NOT");
    }
}
