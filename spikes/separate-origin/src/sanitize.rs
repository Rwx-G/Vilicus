//! The allowlist sanitizer the content origin applies to external HTML before serving it, inside
//! the CSP and the sandbox, which stay the enforcement layers. Only inert presentational elements
//! survive, with no attribute that can carry a URL, a style or a handler: no `<link>`, `<meta>`,
//! `<base>`, script, style, form, frame, plugin, media, image or SVG element, and no `href` on
//! `<a>` (the client shows the links of external content outside the frame).

use std::collections::{HashMap, HashSet};

use ammonia::Builder;

/// Elements kept. Everything else is removed and its text kept, except the elements of
/// [`DROPPED_WITH_CONTENT`].
pub const KEPT_ELEMENTS: &[&str] = &[
    "a",
    "abbr",
    "b",
    "bdi",
    "bdo",
    "blockquote",
    "br",
    "caption",
    "cite",
    "code",
    "col",
    "colgroup",
    "dd",
    "del",
    "dfn",
    "div",
    "dl",
    "dt",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "ins",
    "kbd",
    "li",
    "mark",
    "ol",
    "p",
    "pre",
    "q",
    "s",
    "samp",
    "small",
    "span",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "time",
    "tr",
    "u",
    "ul",
    "var",
    "wbr",
];

/// Elements removed together with their content.
pub const DROPPED_WITH_CONTENT: &[&str] = &["script", "style", "template", "noscript", "title"];

/// Attributes kept on a few table elements; none can hold a URL.
pub const KEPT_ATTRIBUTES: &[(&str, &[&str])] = &[
    ("td", &["colspan", "rowspan"]),
    ("th", &["colspan", "rowspan", "scope"]),
];

/// Attributes kept on every kept element.
pub const KEPT_GENERIC_ATTRIBUTES: &[&str] = &["lang", "dir"];

/// Sanitizes one fragment of external HTML.
pub fn sanitize(html: &str) -> String {
    let tag_attributes: HashMap<&str, HashSet<&str>> = KEPT_ATTRIBUTES
        .iter()
        .map(|(tag, attrs)| (*tag, attrs.iter().copied().collect()))
        .collect();
    Builder::empty()
        .tags(KEPT_ELEMENTS.iter().copied().collect())
        .clean_content_tags(DROPPED_WITH_CONTENT.iter().copied().collect())
        .tag_attributes(tag_attributes)
        .generic_attributes(KEPT_GENERIC_ATTRIBUTES.iter().copied().collect())
        .url_schemes(HashSet::new())
        .link_rel(None)
        .strip_comments(true)
        .clean(html)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{self, ATTACKER_SUFFIX, PASSIVE, SINGLES};

    const APP: &str = "https://vilicus.internal";

    fn forbidden(output: &str) -> Vec<&'static str> {
        [
            "://",
            "<link",
            "<meta",
            "<base",
            "<script",
            "<style",
            "<form",
            "<iframe",
            "<object",
            "<embed",
            "<img",
            "<svg",
            "<video",
            "<audio",
            "<input",
            "<button",
            "href",
            "src",
            "poster",
            "style=",
            "background",
            " on",
            "url(",
            ATTACKER_SUFFIX,
        ]
        .into_iter()
        .filter(|needle| output.to_ascii_lowercase().contains(needle))
        .collect()
    }

    #[test]
    fn every_hostile_fixture_comes_out_inert() {
        let mut names = vec!["passive".to_owned()];
        names.extend(SINGLES.iter().map(|s| s.name.to_owned()));
        names.extend(
            PASSIVE
                .iter()
                .map(|v| format!("{}{}", fixtures::ONLY_PREFIX, v.name)),
        );
        for name in names {
            let (head, body) = fixtures::render_parts(&name, "r1", APP).unwrap_or_default();
            let clean = sanitize(&format!("{head}{body}"));
            assert!(
                forbidden(&clean).is_empty(),
                "{name}: {:?} in {clean}",
                forbidden(&clean)
            );
        }
    }

    #[test]
    fn presentational_markup_survives_and_links_lose_their_target() {
        let clean = sanitize(
            "<p lang=\"fr\">Bonjour <b>x</b> <a href=\"https://example.com/\" title=\"t\">lien</a></p>\
             <table><tr><td colspan=\"2\" style=\"color:red\">c</td></tr></table>",
        );
        assert_eq!(
            clean,
            "<p lang=\"fr\">Bonjour <b>x</b> <a>lien</a></p>\
             <table><tbody><tr><td colspan=\"2\">c</td></tr></tbody></table>"
        );
    }

    #[test]
    fn script_and_style_content_is_dropped_not_shown() {
        assert_eq!(
            sanitize("<script>alert(1)</script><style>p{}</style>ok"),
            "ok"
        );
    }
}
