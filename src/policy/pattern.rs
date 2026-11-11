//! Patterns, as policies write actions, resources and the values of `*Like`
//! conditions: `*` stands for any run of characters (none too), `?` for any
//! one, everything else for itself. In a policy of version `2012-10-17`,
//! `${key}` stands for the request's value of the condition key `key` (or
//! `${key, 'default'}`, for when it has none), and `${*}`, `${?}` and `${$}`
//! for those characters, which then match only themselves; a variable's value
//! is matched literally too, so a user named `*` matches no one else.

use super::Context;

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Char(char),
    /// `*`
    Any,
    /// `?`
    One,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pattern(Vec<Token>);

/// How a pattern's text is read.
#[derive(Clone, Copy)]
pub struct Syntax<'a> {
    /// Whether `*` and `?` are wildcards (else they're themselves).
    pub wildcards: bool,
    /// The request whose values policy variables stand for, if they're
    /// variables (else `${` is text).
    pub variables: Option<&'a Context>,
}

impl Pattern {
    /// Reads `text`; `None` if it names a variable that has no value (and no
    /// default), with which it matches nothing.
    pub fn new(text: &str, syntax: Syntax) -> Option<Pattern> {
        let mut tokens = Vec::new();
        let mut rest = text;
        while let Some(c) = rest.chars().next() {
            if let Some(context) = syntax.variables
                && let Some(after) = rest.strip_prefix("${")
                && let Some(end) = after.find('}')
            {
                let value = match &after[..end] {
                    "*" => "*".to_owned(),
                    "?" => "?".to_owned(),
                    "$" => "$".to_owned(),
                    variable => resolve(variable, context)?,
                };
                tokens.extend(value.chars().map(Token::Char));
                rest = &after[end + 1..];
                continue;
            }
            tokens.push(match c {
                '*' if syntax.wildcards => Token::Any,
                '?' if syntax.wildcards => Token::One,
                c => Token::Char(c),
            });
            rest = &rest[c.len_utf8()..];
        }
        Some(Pattern(tokens))
    }

    /// Whether `text` matches, character by character, exactly or (with
    /// `ignore_case`) regardless of case.
    pub fn matches(&self, text: &str, ignore_case: bool) -> bool {
        let text: Vec<char> = text.chars().collect();
        let same = |a: char, b: char| a == b || (ignore_case && a.to_lowercase().eq(b.to_lowercase()));
        // The classic wildcard match: on a mismatch, let the last `*` take
        // one more character, and go on from there.
        let (tokens, mut t, mut s) = (&self.0, 0, 0);
        let mut star: Option<(usize, usize)> = None;
        while s < text.len() {
            match tokens.get(t) {
                Some(Token::Any) => {
                    star = Some((t, s));
                    t += 1;
                }
                Some(Token::One) => {
                    t += 1;
                    s += 1;
                }
                Some(Token::Char(c)) if same(*c, text[s]) => {
                    t += 1;
                    s += 1;
                }
                _ => match star {
                    Some((star_t, star_s)) => {
                        star = Some((star_t, star_s + 1));
                        t = star_t + 1;
                        s = star_s + 1;
                    }
                    None => return false,
                },
            }
        }
        tokens[t..].iter().all(|token| *token == Token::Any)
    }
}

/// A variable's value: `name` or `name, 'default'`.
fn resolve(variable: &str, context: &Context) -> Option<String> {
    let (name, default) = match variable.split_once(',') {
        Some((name, default)) => {
            let default = default.trim();
            let default = default.strip_prefix('\'').and_then(|d| d.strip_suffix('\''));
            (name.trim(), default)
        }
        None => (variable, None),
    };
    // Only single values stand in for variables.
    match context.get(name) {
        Some([value]) => Some(value.clone()),
        _ => default.map(str::to_owned),
    }
}

/// Splits an ARN into its six parts (the last may hold `:`s), or `None` if
/// it has fewer.
pub fn arn_parts(arn: &str) -> Option<[&str; 6]> {
    let mut parts = arn.splitn(6, ':');
    let mut next = || parts.next();
    Some([next()?, next()?, next()?, next()?, next()?, next()?])
}

/// Whether `arn` matches the ARN pattern `pattern`: each of its six parts on
/// its own, so a wildcard doesn't reach across one; `*` alone matches
/// anything. Variables only in the last part (the resource).
pub fn arn_matches(pattern: &str, arn: &str, variables: Option<&Context>) -> bool {
    if pattern == "*" {
        return true;
    }
    let (Some(pattern), Some(arn)) = (arn_parts(pattern), arn_parts(arn)) else { return false };
    pattern.iter().zip(arn).enumerate().all(|(i, (pattern, part))| {
        let syntax = Syntax { wildcards: true, variables: if i == 5 { variables } else { None } };
        Pattern::new(pattern, syntax).is_some_and(|p| p.matches(part, false))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(pattern: &str, text: &str) -> bool {
        Pattern::new(pattern, Syntax { wildcards: true, variables: None }).unwrap().matches(text, false)
    }

    #[test]
    fn matches_wildcards() {
        assert!(glob("*", ""));
        assert!(glob("a*", "a"));
        assert!(glob("a*c", "abbbc"));
        assert!(glob("a?c", "abc"));
        assert!(!glob("a?c", "ac"));
        assert!(glob("*a*b*", "xxaxxbxx"));
        assert!(!glob("*a*b*", "xxbxxaxx"));
        assert!(glob("é?", "éü"));
        assert!(!glob("abc", "ABC"));
        let pattern = Pattern::new("s3:get*", Syntax { wildcards: true, variables: None }).unwrap();
        assert!(pattern.matches("S3:GetObject", true));
    }

    /// The S3 user guide's example of `/` being an ordinary character.
    #[test]
    fn a_wildcard_spans_slashes() {
        let pattern = "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*/test/*";
        for key in ["1/2/test/3/object.jpg", "1///test///object.jpg", "1//test/object.jpg", "1/test/"] {
            assert!(arn_matches(pattern, &format!("arn:aws:s3:::DOC-EXAMPLE-BUCKET/{key}"), None), "{key}");
        }
        for key in ["test/object.jpg", "1-test/object.jpg", "1/2/test.jpg"] {
            assert!(!arn_matches(pattern, &format!("arn:aws:s3:::DOC-EXAMPLE-BUCKET/{key}"), None), "{key}");
        }
    }

    /// The IAM guide's example: `StringLike` reaches across `:`, an ARN's
    /// wildcard doesn't.
    #[test]
    fn an_arn_wildcard_stays_in_its_part() {
        let pattern = "arn:aws:someservice:*:111122223333:finance/*";
        let arn = "arn:aws:someservice:us-east-2:999999999999:store/abc:111122223333:finance/document.txt";
        assert!(glob(pattern, arn));
        assert!(!arn_matches(pattern, arn, None));
        assert!(arn_matches("arn:aws:s3:::b*", "arn:aws:s3:::bucket", None));
        assert!(!arn_matches("arn:aws:s3:::b", "arn:aws:s3", None));
        assert!(arn_matches("*", "anything", None));
    }

    #[test]
    fn variables_stand_for_literal_values() {
        let mut context = Context::default();
        context.set("aws:username", "*");
        let syntax = Syntax { wildcards: true, variables: Some(&context) };
        let home = Pattern::new("home/${aws:username}/*", syntax).unwrap();
        assert!(home.matches("home/*/file", false));
        assert!(!home.matches("home/alice/file", false));
        // Names are case-insensitive.
        assert!(Pattern::new("${AWS:UserName}", syntax).unwrap().matches("*", false));
        // Escapes.
        let escaped = Pattern::new("a${*}b${?}${$}", syntax).unwrap();
        assert!(escaped.matches("a*b?$", false));
        assert!(!escaped.matches("axb?$", false));
        // No value: no match, unless there's a default.
        assert_eq!(Pattern::new("${aws:userid}", syntax), None);
        let default = Pattern::new("team/${aws:PrincipalTag/team, 'company-wide'}/*", syntax).unwrap();
        assert!(default.matches("team/company-wide/x", false));
        // Not a variable at all without a closing brace, or before 2012-10-17.
        assert!(Pattern::new("${aws:username", syntax).unwrap().matches("${aws:username", false));
        let old = Syntax { wildcards: true, variables: None };
        assert!(Pattern::new("${aws:username}", old).unwrap().matches("${aws:username}", false));
    }
}
