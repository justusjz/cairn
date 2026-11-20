//! S3 Select's SQL: a `SELECT` over one object, as AWS's guide to it
//! describes it.
//!
//! ```text
//! SELECT * | item [, item]...
//! FROM S3Object[[*]] [[AS] alias]
//! [WHERE condition]
//! [LIMIT n]
//! ```
//!
//! Its expressions: literals (numbers, `'strings'`, `TRUE`, `FALSE`, `NULL`,
//! `MISSING`, and `` `timestamps` ``); paths (`s.name`, `s."Name"`, `_1`,
//! `s.a.b[0]`); `||`, arithmetic, comparisons, `AND`, `OR`, `NOT`,
//! `IS [NOT] NULL|MISSING`, `[NOT] LIKE ... [ESCAPE ...]`, `[NOT] BETWEEN`,
//! `[NOT] IN (...)`; `CASE`; `CAST`; the functions `CHAR_LENGTH`,
//! `CHARACTER_LENGTH`, `LOWER`, `UPPER`, `TRIM`, `SUBSTRING`, `COALESCE`,
//! `NULLIF`, `DATE_ADD`, `DATE_DIFF`, `EXTRACT`, `TO_STRING`,
//! `TO_TIMESTAMP` and `UTCNOW`; and the aggregates `COUNT`, `SUM`, `AVG`,
//! `MIN` and `MAX`. Not (yet) paths into the object in `FROM`.

use super::SelectError;
use super::timestamp::{Part, Timestamp};
use super::value::Value;

/// The longest expression S3 Select takes, in bytes (its documented limit).
pub const MAX_EXPRESSION: usize = 256 * 1024;

/// How deeply expressions may nest: parsing, evaluating and dropping them
/// recurse.
const MAX_DEPTH: usize = 128;

/// How many binary operators a query may have.
const MAX_LINKS: usize = 1000;

/// A parsed query.
#[derive(Debug)]
pub struct Query {
    pub projection: Projection,
    pub condition: Option<Expr>,
    pub limit: Option<u64>,
    /// The aggregates the projection uses (see `Expr::Aggregate`). If there
    /// are any, the query answers with a single record.
    pub aggregates: Vec<Aggregate>,
}

#[derive(Debug)]
pub enum Projection {
    /// `SELECT *`: each record as it is.
    Star,
    Items(Vec<Item>),
}

#[derive(Debug)]
pub struct Item {
    pub expr: Expr,
    /// What JSON output names it: its alias, else its path's last name,
    /// else `_N` for the Nth item.
    pub name: String,
}

#[derive(Debug, Clone)]
pub enum Step {
    /// A name: matched regardless of case unless it was quoted.
    Field {
        name: String,
        quoted: bool,
    },
    Index(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Concat,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Bool,
    Int,
    Float,
    String,
    Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trim {
    Leading,
    Trailing,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Function {
    CharLength,
    Lower,
    Upper,
    Coalesce,
    NullIf,
    /// `TO_STRING(timestamp, pattern)`.
    ToString,
    /// `TO_TIMESTAMP(string)`.
    ToTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateKind {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

#[derive(Debug)]
pub struct Aggregate {
    pub kind: AggregateKind,
    /// `None` for `COUNT(*)`.
    pub arg: Option<Expr>,
}

#[derive(Debug)]
pub enum Expr {
    Literal(Value),
    /// A path into the record (the alias already taken off). An empty one
    /// is the record itself.
    Path(Vec<Step>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// `IS [NOT] NULL` (`missing` false) or `IS [NOT] MISSING`.
    Is {
        expr: Box<Expr>,
        missing: bool,
        negated: bool,
    },
    Like {
        expr: Box<Expr>,
        pattern: Box<Expr>,
        escape: Option<Box<Expr>>,
        negated: bool,
    },
    Between {
        expr: Box<Expr>,
        low: Box<Expr>,
        high: Box<Expr>,
        negated: bool,
    },
    In {
        expr: Box<Expr>,
        list: Vec<Expr>,
        negated: bool,
    },
    Case {
        operand: Option<Box<Expr>>,
        whens: Vec<(Expr, Expr)>,
        otherwise: Option<Box<Expr>>,
    },
    Cast(Box<Expr>, Type),
    Trim {
        side: Trim,
        chars: Option<Box<Expr>>,
        expr: Box<Expr>,
    },
    Substring {
        expr: Box<Expr>,
        start: Box<Expr>,
        length: Option<Box<Expr>>,
    },
    Call(Function, Vec<Expr>),
    /// `DATE_ADD(part, quantity, timestamp)`.
    DateAdd {
        part: Part,
        quantity: Box<Expr>,
        timestamp: Box<Expr>,
    },
    /// `DATE_DIFF(part, from, to)`.
    DateDiff {
        part: Part,
        from: Box<Expr>,
        to: Box<Expr>,
    },
    /// `EXTRACT(part FROM timestamp)`.
    Extract {
        part: Part,
        timestamp: Box<Expr>,
    },
    /// The result of the query's `n`th aggregate.
    Aggregate(usize),
}

/// Parses `sql`.
pub fn parse(sql: &str) -> Result<Query, SelectError> {
    if sql.len() > MAX_EXPRESSION {
        return Err(SelectError::new(
            "ExpressionTooLong",
            "The SQL expression is too long: the maximum byte-length for the SQL expression is 256 KB.",
        ));
    }
    let tokens = lex(sql)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        alias: None,
        aggregates: Vec::new(),
        in_aggregate: false,
        aggregates_allowed: true,
        depth: 0,
        links: 0,
    };
    let query = parser.query()?;
    let exprs = query.condition.iter().chain(
        match &query.projection {
            Projection::Star => None,
            Projection::Items(items) => Some(items.iter().map(|i| &i.expr)),
        }
        .into_iter()
        .flatten(),
    );
    let aggregated = query.aggregates.iter().filter_map(|a| a.arg.as_ref());
    if exprs.chain(aggregated).any(|e| too_deep_at(e, MAX_DEPTH)) {
        return Err(too_deep());
    }
    Ok(query)
}

// ---- Lexing ----

#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// An unquoted identifier or keyword, as written.
    Ident(String),
    /// A `"quoted"` identifier.
    Quoted(String),
    Str(String),
    Int(i64),
    Float(f64),
    /// A `` `timestamp` ``: an Ion literal, of which S3 Select's SQL has
    /// timestamps.
    Timestamp(Timestamp),
    Sym(&'static str),
    End,
}

const SYMBOLS: &[&str] = &[
    "<>", "!=", "<=", ">=", "||", "(", ")", ",", ".", "*", "+", "-", "/", "%", "=", "<", ">", "[",
    "]",
];

fn lex(sql: &str) -> Result<Vec<Token>, SelectError> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Comments: `-- to the end of the line`, and `/* ... */`.
        if sql[i..].starts_with("--") {
            i = sql[i..].find('\n').map_or(bytes.len(), |n| i + n);
            continue;
        }
        if sql[i..].starts_with("/*") {
            match sql[i + 2..].find("*/") {
                Some(n) => i += n + 4,
                None => return Err(lexer("LexerInvalidChar", "an unterminated comment")),
            }
            continue;
        }
        if c == b'`' {
            let Some(n) = sql[i + 1..].find('`') else {
                return Err(lexer("LexerInvalidLiteral", "an unterminated `literal`"));
            };
            let text = &sql[i + 1..i + 1 + n];
            match Timestamp::parse(text) {
                Ok(timestamp) => tokens.push(Token::Timestamp(timestamp)),
                Err(_) => {
                    return Err(lexer(
                        "LexerInvalidLiteral",
                        &format!("the literal `{text}`, which isn't a timestamp"),
                    ));
                }
            }
            i += n + 2;
            continue;
        }
        if c == b'\'' || c == b'"' {
            // Doubled, the quote stands for itself.
            let mut text = String::new();
            let mut j = i + 1;
            loop {
                let Some(n) = sql[j..].find(c as char) else {
                    let what = if c == b'\'' {
                        "a string"
                    } else {
                        "an identifier"
                    };
                    return Err(lexer(
                        "LexerInvalidLiteral",
                        &format!("an unterminated {what}"),
                    ));
                };
                text.push_str(&sql[j..j + n]);
                j += n + 1;
                if bytes.get(j) == Some(&c) {
                    text.push(c as char);
                    j += 1;
                } else {
                    break;
                }
            }
            tokens.push(if c == b'\'' {
                Token::Str(text)
            } else {
                Token::Quoted(text)
            });
            i = j;
            continue;
        }
        if c.is_ascii_digit() || (c == b'.' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let mut float = false;
            if bytes.get(j) == Some(&b'.') {
                float = true;
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
            }
            if matches!(bytes.get(j), Some(b'e' | b'E')) {
                let mut k = j + 1;
                if matches!(bytes.get(k), Some(b'+' | b'-')) {
                    k += 1;
                }
                if bytes.get(k).is_some_and(u8::is_ascii_digit) {
                    float = true;
                    j = k;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        j += 1;
                    }
                }
            }
            let text = &sql[i..j];
            let token = match float {
                false => text.parse().map(Token::Int).ok(),
                true => None,
            };
            let token = token.or_else(|| text.parse().map(Token::Float).ok());
            match token {
                Some(token) => tokens.push(token),
                None => {
                    return Err(lexer("LexerInvalidLiteral", &format!("the number {text}")));
                }
            }
            i = j;
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            tokens.push(Token::Ident(sql[i..j].to_owned()));
            i = j;
            continue;
        }
        match SYMBOLS.iter().find(|s| sql[i..].starts_with(**s)) {
            Some(symbol) => {
                tokens.push(Token::Sym(symbol));
                i += symbol.len();
            }
            None => {
                let c = sql[i..].chars().next().unwrap_or('?');
                return Err(lexer("LexerInvalidChar", &format!("the character {c:?}")));
            }
        }
    }
    tokens.push(Token::End);
    Ok(tokens)
}

fn lexer(code: &'static str, what: &str) -> SelectError {
    SelectError::new(code, format!("The SQL expression contains {what}."))
}

// ---- Parsing ----

/// Words that can't be an alias, or a path's first name.
const RESERVED: &[&str] = &[
    "select", "from", "where", "limit", "and", "or", "not", "is", "null", "missing", "like",
    "escape", "between", "in", "case", "when", "then", "else", "end", "cast", "as", "true",
    "false", "group", "order", "having", "join", "union",
];

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    /// The `FROM`'s alias, which paths may start with.
    alias: Option<String>,
    aggregates: Vec<Aggregate>,
    /// Whether an aggregate's argument is being parsed (they don't nest).
    in_aggregate: bool,
    /// Whether aggregates may be used here (in the projection only).
    aggregates_allowed: bool,
    /// How deeply the parse is nested now.
    depth: usize,
    /// How many binary operators the query has so far: their chains are
    /// parsed in loops, not nested, but make the expression as deep.
    links: usize,
}

fn unexpected(token: &Token) -> SelectError {
    let what = match token {
        Token::End => "the end of the expression".to_owned(),
        Token::Ident(s) => format!("'{s}'"),
        Token::Quoted(s) => format!("\"{s}\""),
        Token::Str(s) => format!("the string '{s}'"),
        Token::Int(i) => i.to_string(),
        Token::Float(f) => f.to_string(),
        Token::Timestamp(t) => format!("`{}`", t.to_text()),
        Token::Sym(s) => format!("'{s}'"),
    };
    SelectError::new(
        "ParseUnexpectedToken",
        format!("The SQL expression contains an unexpected token: {what}."),
    )
}

fn unsupported(what: &str) -> SelectError {
    SelectError::new(
        "UnsupportedSyntax",
        format!("{what} isn't supported in S3 Select's SQL here."),
    )
}

impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn peek_at(&self, n: usize) -> &Token {
        &self.tokens[(self.pos + n).min(self.tokens.len() - 1)]
    }

    fn next(&mut self) -> Token {
        let token = self.tokens[self.pos].clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        token
    }

    /// Whether the next token is the keyword `word`.
    fn at(&self, word: &str) -> bool {
        matches!(self.peek(), Token::Ident(s) if s.eq_ignore_ascii_case(word))
    }

    fn at_sym(&self, symbol: &str) -> bool {
        matches!(self.peek(), Token::Sym(s) if *s == symbol)
    }

    fn eat(&mut self, word: &str) -> bool {
        let at = self.at(word);
        if at {
            self.next();
        }
        at
    }

    fn eat_sym(&mut self, symbol: &str) -> bool {
        let at = self.at_sym(symbol);
        if at {
            self.next();
        }
        at
    }

    fn expect(&mut self, word: &str) -> Result<(), SelectError> {
        match self.eat(word) {
            true => Ok(()),
            false => Err(SelectError::new(
                "ParseExpectedKeyword",
                format!(
                    "The SQL expression expects the keyword {} here, not {}.",
                    word.to_ascii_uppercase(),
                    describe(self.peek())
                ),
            )),
        }
    }

    fn expect_sym(&mut self, symbol: &str) -> Result<(), SelectError> {
        match self.eat_sym(symbol) {
            true => Ok(()),
            false => Err(SelectError::new(
                "ParseExpectedTokenType",
                format!(
                    "The SQL expression expects '{symbol}' here, not {}.",
                    describe(self.peek())
                ),
            )),
        }
    }

    fn query(&mut self) -> Result<Query, SelectError> {
        self.expect("select")?;
        // The projection is parsed after FROM, which names the alias its
        // paths may start with.
        let start = self.pos;
        let mut depth = 0usize;
        loop {
            match self.peek() {
                Token::End => {
                    return Err(SelectError::new(
                        "ParseSelectMissingFrom",
                        "The SQL expression has no FROM clause.",
                    ));
                }
                Token::Sym("(") | Token::Sym("[") => depth += 1,
                Token::Sym(")") | Token::Sym("]") => depth = depth.saturating_sub(1),
                Token::Ident(s) if depth == 0 && s.eq_ignore_ascii_case("from") => break,
                _ => {}
            }
            self.next();
        }
        let from = self.pos;
        self.from()?;
        let condition = match self.eat("where") {
            true => {
                self.aggregates_allowed = false;
                let condition = self.expr(0)?;
                self.aggregates_allowed = true;
                Some(condition)
            }
            false => None,
        };
        let limit = match self.eat("limit") {
            true => match self.next() {
                Token::Int(n) if n >= 0 => Some(n as u64),
                Token::Sym("-") => {
                    return Err(SelectError::new(
                        "EvaluatorNegativeLimit",
                        "The LIMIT can't be negative.",
                    ));
                }
                token => return Err(unexpected(&token)),
            },
            false => None,
        };
        for clause in ["group", "order", "having", "union", "join"] {
            if self.at(clause) {
                return Err(unsupported(&clause.to_ascii_uppercase()));
            }
        }
        if *self.peek() != Token::End {
            return Err(unexpected(self.peek()));
        }
        let end = self.pos;
        // Back to the projection.
        self.pos = start;
        let projection = self.projection(from)?;
        self.pos = end;
        if !self.aggregates.is_empty()
            && let Projection::Items(items) = &projection
            && items.iter().any(|item| reads_record(&item.expr))
        {
            return Err(SelectError::new(
                "ParseUnsupportedSyntax",
                "A query with aggregates may only select aggregates (S3 Select has no GROUP BY).",
            ));
        }
        Ok(Query {
            projection,
            condition,
            limit,
            aggregates: std::mem::take(&mut self.aggregates),
        })
    }

    /// `FROM S3Object[[*]] [[AS] alias]`.
    fn from(&mut self) -> Result<(), SelectError> {
        self.expect("from")?;
        match self.next() {
            Token::Ident(s) if s.eq_ignore_ascii_case("s3object") => {}
            Token::Ident(s) | Token::Quoted(s) => {
                return Err(SelectError::new(
                    "InvalidDataSource",
                    format!("The SQL expression's FROM is {s}: it must be S3Object."),
                ));
            }
            token => return Err(unexpected(&token)),
        }
        if self.at_sym("[") {
            if self.peek_at(1) == &Token::Sym("*") && self.peek_at(2) == &Token::Sym("]") {
                self.pos += 3;
            } else {
                return Err(unsupported("A path into the object in FROM"));
            }
        }
        if self.at_sym(".") || self.at_sym("[") {
            return Err(unsupported("A path into the object in FROM"));
        }
        let explicit = self.eat("as");
        match self.peek().clone() {
            Token::Ident(s) if !RESERVED.iter().any(|r| s.eq_ignore_ascii_case(r)) => {
                self.next();
                self.alias = Some(s);
            }
            Token::Quoted(s) => {
                self.next();
                self.alias = Some(s);
            }
            token if explicit => {
                return Err(SelectError::new(
                    "ParseExpectedIdentForAlias",
                    format!(
                        "The SQL expression expects an alias after AS, not {}.",
                        describe(&token)
                    ),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// The projection, which ends at `from`.
    fn projection(&mut self, from: usize) -> Result<Projection, SelectError> {
        if self.at_sym("*") && self.pos + 1 == from {
            self.next();
            return Ok(Projection::Star);
        }
        let mut items = Vec::new();
        loop {
            if self.at_sym("*") {
                return Err(SelectError::new(
                    "ParseAsteriskIsNotAloneInSelectList",
                    "Other expressions can't be selected with *.",
                ));
            }
            if self.pos == from {
                return Err(SelectError::new(
                    "ParseEmptySelect",
                    "The SQL expression selects nothing.",
                ));
            }
            let expr = self.expr(0)?;
            let alias = match self.eat("as") {
                true => match self.next() {
                    Token::Ident(s) | Token::Quoted(s) => Some(s),
                    token => {
                        return Err(SelectError::new(
                            "ParseExpectedIdentForAlias",
                            format!(
                                "The SQL expression expects an alias after AS, not {}.",
                                describe(&token)
                            ),
                        ));
                    }
                },
                false => match self.peek().clone() {
                    Token::Ident(s) if self.pos != from => {
                        self.next();
                        Some(s)
                    }
                    Token::Quoted(s) => {
                        self.next();
                        Some(s)
                    }
                    _ => None,
                },
            };
            let name = alias
                .or_else(|| match &expr {
                    Expr::Path(steps) => match steps.last() {
                        Some(Step::Field { name, .. }) => Some(name.clone()),
                        _ => None,
                    },
                    _ => None,
                })
                .unwrap_or_else(|| format!("_{}", items.len() + 1));
            items.push(Item { expr, name });
            if self.pos == from {
                break;
            }
            self.expect_sym(",")?;
        }
        Ok(Projection::Items(items))
    }

    /// An expression whose operators bind at least as tightly as `level`'s
    /// (0: OR, 1: AND, 2: NOT, 3: comparisons, 4: `||`, 5: `+ -`, 6: `* / %`).
    fn expr(&mut self, level: u8) -> Result<Expr, SelectError> {
        self.nested(|p| p.expr_at(level))
    }

    /// Runs `parse` a level deeper, refusing what nests too deeply.
    fn nested<T>(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<T, SelectError>,
    ) -> Result<T, SelectError> {
        if self.depth >= MAX_DEPTH {
            return Err(too_deep());
        }
        self.depth += 1;
        let result = parse(self);
        self.depth -= 1;
        result
    }

    fn expr_at(&mut self, level: u8) -> Result<Expr, SelectError> {
        match level {
            0 => self.chain(1, |p| p.eat("or").then_some(BinOp::Or)),
            1 => self.chain(2, |p| p.eat("and").then_some(BinOp::And)),
            2 => match self.eat("not") {
                true => Ok(Expr::Not(Box::new(self.expr(2)?))),
                false => self.expr(3),
            },
            3 => self.comparison(),
            4 => self.chain(5, |p| p.eat_sym("||").then_some(BinOp::Concat)),
            5 => self.chain(6, |p| {
                if p.eat_sym("+") {
                    Some(BinOp::Add)
                } else if p.eat_sym("-") {
                    Some(BinOp::Sub)
                } else {
                    None
                }
            }),
            6 => self.chain(7, |p| {
                if p.eat_sym("*") {
                    Some(BinOp::Mul)
                } else if p.eat_sym("/") {
                    Some(BinOp::Div)
                } else if p.eat_sym("%") {
                    Some(BinOp::Mod)
                } else {
                    None
                }
            }),
            _ => self.unary(),
        }
    }

    /// Operands of `next`'s level joined by `op`, left to right. Each link
    /// nests the expression one deeper: there may be `MAX_LINKS` in all (and
    /// `parse` checks the expression's depth).
    fn chain(
        &mut self,
        next: u8,
        op: impl Fn(&mut Self) -> Option<BinOp>,
    ) -> Result<Expr, SelectError> {
        let mut left = self.expr(next)?;
        while let Some(op) = op(self) {
            self.links += 1;
            if self.links > MAX_LINKS {
                return Err(too_deep());
            }
            let right = self.expr(next)?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn comparison(&mut self) -> Result<Expr, SelectError> {
        let left = self.expr(4)?;
        let op = match self.peek() {
            Token::Sym("=") => Some(BinOp::Eq),
            Token::Sym("<>" | "!=") => Some(BinOp::Ne),
            Token::Sym("<") => Some(BinOp::Lt),
            Token::Sym("<=") => Some(BinOp::Le),
            Token::Sym(">") => Some(BinOp::Gt),
            Token::Sym(">=") => Some(BinOp::Ge),
            _ => None,
        };
        if let Some(op) = op {
            self.next();
            let right = self.expr(4)?;
            return Ok(Expr::Binary(op, Box::new(left), Box::new(right)));
        }
        if self.eat("is") {
            let negated = self.eat("not");
            let missing = if self.eat("null") {
                false
            } else if self.eat("missing") {
                true
            } else {
                return Err(SelectError::new(
                    "ParseExpectedKeyword",
                    format!(
                        "The SQL expression expects NULL or MISSING after IS, not {}.",
                        describe(self.peek())
                    ),
                ));
            };
            return Ok(Expr::Is {
                expr: Box::new(left),
                missing,
                negated,
            });
        }
        let negated = self.at("not")
            && matches!(self.peek_at(1), Token::Ident(s)
                if ["like", "between", "in"].iter().any(|w| s.eq_ignore_ascii_case(w)));
        if negated {
            self.next();
        }
        if self.eat("like") {
            let pattern = self.expr(4)?;
            let escape = match self.eat("escape") {
                true => Some(Box::new(self.expr(4)?)),
                false => None,
            };
            return Ok(Expr::Like {
                expr: Box::new(left),
                pattern: Box::new(pattern),
                escape,
                negated,
            });
        }
        if self.eat("between") {
            let low = self.expr(4)?;
            self.expect("and")?;
            let high = self.expr(4)?;
            return Ok(Expr::Between {
                expr: Box::new(left),
                low: Box::new(low),
                high: Box::new(high),
                negated,
            });
        }
        if self.eat("in") {
            self.expect_sym("(")?;
            let mut list = vec![self.expr(0)?];
            while self.eat_sym(",") {
                list.push(self.expr(0)?);
            }
            self.expect_sym(")")?;
            return Ok(Expr::In {
                expr: Box::new(left),
                list,
                negated,
            });
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, SelectError> {
        if self.eat_sym("-") {
            return Ok(match self.nested(|p| p.unary())? {
                Expr::Literal(Value::Int(i)) => Expr::Literal(Value::Int(-i)),
                Expr::Literal(Value::Float(f)) => Expr::Literal(Value::Float(-f)),
                expr => Expr::Neg(Box::new(expr)),
            });
        }
        if self.eat_sym("+") {
            return self.nested(|p| p.unary());
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, SelectError> {
        let token = self.next();
        match token {
            Token::Int(i) => Ok(Expr::Literal(Value::Int(i))),
            Token::Float(f) => Ok(Expr::Literal(Value::Float(f))),
            Token::Timestamp(t) => Ok(Expr::Literal(Value::Timestamp(t))),
            Token::Str(s) => Ok(Expr::Literal(Value::Str(s))),
            Token::Sym("(") => {
                let expr = self.expr(0)?;
                self.expect_sym(")")?;
                Ok(expr)
            }
            Token::Quoted(name) => self.path(name, true),
            Token::Ident(word) => {
                let lower = word.to_ascii_lowercase();
                match lower.as_str() {
                    "true" => Ok(Expr::Literal(Value::Bool(true))),
                    "false" => Ok(Expr::Literal(Value::Bool(false))),
                    "null" => Ok(Expr::Literal(Value::Null)),
                    "missing" => Ok(Expr::Literal(Value::Missing)),
                    "case" => self.case(),
                    _ if self.at_sym("(") => self.call(&lower),
                    _ if RESERVED.contains(&lower.as_str()) => Err(unexpected(&Token::Ident(word))),
                    _ => self.path(word, false),
                }
            }
            token => Err(match token {
                Token::End => SelectError::new(
                    "ParseExpectedExpression",
                    "The SQL expression ends where it expects an expression.",
                ),
                token => unexpected(&token),
            }),
        }
    }

    /// A path starting with the name `first`.
    fn path(&mut self, first: String, quoted: bool) -> Result<Expr, SelectError> {
        let mut steps = vec![Step::Field {
            name: first,
            quoted,
        }];
        loop {
            if self.eat_sym(".") {
                match self.next() {
                    Token::Ident(name) => steps.push(Step::Field {
                        name,
                        quoted: false,
                    }),
                    Token::Quoted(name) => steps.push(Step::Field { name, quoted: true }),
                    Token::Sym("*") => return Err(unsupported("A wildcard in a path")),
                    token => return Err(unexpected(&token)),
                }
            } else if self.eat_sym("[") {
                match self.next() {
                    Token::Int(i) if i >= 0 => steps.push(Step::Index(i as usize)),
                    Token::Str(name) => steps.push(Step::Field { name, quoted: true }),
                    Token::Sym("*") => return Err(unsupported("A wildcard in a path")),
                    token => return Err(unexpected(&token)),
                }
                self.expect_sym("]")?;
            } else {
                break;
            }
        }
        // The alias (or `S3Object`) names the record: paths may start with it.
        if let Some(Step::Field {
            name,
            quoted: false,
        }) = steps.first()
        {
            let names_record = name.eq_ignore_ascii_case("s3object")
                || self
                    .alias
                    .as_ref()
                    .is_some_and(|alias| alias.eq_ignore_ascii_case(name));
            if names_record {
                steps.remove(0);
            }
        }
        Ok(Expr::Path(steps))
    }

    fn case(&mut self) -> Result<Expr, SelectError> {
        let operand = match self.at("when") {
            true => None,
            false => Some(Box::new(self.expr(0)?)),
        };
        let mut whens = Vec::new();
        while self.eat("when") {
            let when = self.expr(0)?;
            self.expect("then")?;
            whens.push((when, self.expr(0)?));
        }
        if whens.is_empty() {
            return Err(SelectError::new(
                "ParseExpectedWhenClause",
                "The SQL expression's CASE has no WHEN.",
            ));
        }
        let otherwise = match self.eat("else") {
            true => Some(Box::new(self.expr(0)?)),
            false => None,
        };
        self.expect("end")?;
        Ok(Expr::Case {
            operand,
            whens,
            otherwise,
        })
    }

    /// A date part: `YEAR` to `SECOND`, and with `timezone`,
    /// `TIMEZONE_HOUR` and `TIMEZONE_MINUTE` (`EXTRACT`'s).
    fn date_part(&mut self, timezone: bool) -> Result<Part, SelectError> {
        let token = self.next();
        let part = match &token {
            Token::Ident(name) => Part::parse(name),
            _ => None,
        };
        match part {
            Some(Part::TimezoneHour | Part::TimezoneMinute) if !timezone => {}
            Some(part) => return Ok(part),
            None => {}
        }
        let parts = match timezone {
            true => "YEAR, MONTH, DAY, HOUR, MINUTE, SECOND, TIMEZONE_HOUR or TIMEZONE_MINUTE",
            false => "YEAR, MONTH, DAY, HOUR, MINUTE or SECOND",
        };
        Err(SelectError::new(
            "ParseExpectedDatePart",
            format!(
                "The SQL expression expects a date part ({parts}) here, not {}.",
                describe(&token)
            ),
        ))
    }

    /// A call of the function `name` (lowercase), at its `(`.
    fn call(&mut self, name: &str) -> Result<Expr, SelectError> {
        self.expect_sym("(")?;
        let expr = match name {
            "cast" => {
                let expr = self.expr(0)?;
                self.expect("as")?;
                let ty = match self.next() {
                    Token::Ident(t) => match t.to_ascii_lowercase().as_str() {
                        "bool" | "boolean" => Type::Bool,
                        "int" | "integer" => Type::Int,
                        "float" | "decimal" | "numeric" => Type::Float,
                        "string" => Type::String,
                        "timestamp" => Type::Timestamp,
                        _ => return Err(expected_type(&Token::Ident(t))),
                    },
                    token => return Err(expected_type(&token)),
                };
                // DECIMAL(p, s)'s precision and scale.
                if matches!(ty, Type::Float) && self.eat_sym("(") {
                    while !self.eat_sym(")") {
                        if self.next() == Token::End {
                            return Err(unexpected(&Token::End));
                        }
                    }
                }
                Expr::Cast(Box::new(expr), ty)
            }
            "trim" => {
                let side = if self.eat("leading") {
                    Some(Trim::Leading)
                } else if self.eat("trailing") {
                    Some(Trim::Trailing)
                } else if self.eat("both") {
                    Some(Trim::Both)
                } else {
                    None
                };
                // TRIM([side] [chars FROM] s), TRIM(side FROM s), TRIM(s).
                let (chars, expr) = if side.is_some() && self.eat("from") {
                    (None, self.expr(0)?)
                } else {
                    let first = self.expr(0)?;
                    match self.eat("from") {
                        true => (Some(Box::new(first)), self.expr(0)?),
                        false => (None, first),
                    }
                };
                Expr::Trim {
                    side: side.unwrap_or(Trim::Both),
                    chars,
                    expr: Box::new(expr),
                }
            }
            "substring" => {
                let expr = self.expr(0)?;
                let (start, length) = if self.eat("from") {
                    let start = self.expr(0)?;
                    let length = match self.eat("for") {
                        true => Some(Box::new(self.expr(0)?)),
                        false => None,
                    };
                    (start, length)
                } else {
                    self.expect_sym(",")?;
                    let start = self.expr(0)?;
                    let length = match self.eat_sym(",") {
                        true => Some(Box::new(self.expr(0)?)),
                        false => None,
                    };
                    (start, length)
                };
                Expr::Substring {
                    expr: Box::new(expr),
                    start: Box::new(start),
                    length,
                }
            }
            "count" | "sum" | "avg" | "min" | "max" => {
                let kind = match name {
                    "count" => AggregateKind::Count,
                    "sum" => AggregateKind::Sum,
                    "avg" => AggregateKind::Avg,
                    "min" => AggregateKind::Min,
                    _ => AggregateKind::Max,
                };
                if !self.aggregates_allowed || self.in_aggregate {
                    return Err(SelectError::new(
                        "ParseUnsupportedSyntax",
                        format!(
                            "{} can only be used in the SELECT list, and not within another aggregate.",
                            name.to_ascii_uppercase()
                        ),
                    ));
                }
                let arg = if kind == AggregateKind::Count && self.at_sym("*") {
                    self.next();
                    None
                } else {
                    if self.at_sym("*") {
                        return Err(SelectError::new(
                            "ParseUnsupportedCallWithStar",
                            format!("{} can't be called with *.", name.to_ascii_uppercase()),
                        ));
                    }
                    self.in_aggregate = true;
                    let arg = self.expr(0);
                    self.in_aggregate = false;
                    Some(arg?)
                };
                self.aggregates.push(Aggregate { kind, arg });
                Expr::Aggregate(self.aggregates.len() - 1)
            }
            "date_add" => {
                let part = self.date_part(false)?;
                self.expect_sym(",")?;
                let quantity = self.expr(0)?;
                self.expect_sym(",")?;
                Expr::DateAdd {
                    part,
                    quantity: Box::new(quantity),
                    timestamp: Box::new(self.expr(0)?),
                }
            }
            "date_diff" => {
                let part = self.date_part(false)?;
                self.expect_sym(",")?;
                let from = self.expr(0)?;
                self.expect_sym(",")?;
                Expr::DateDiff {
                    part,
                    from: Box::new(from),
                    to: Box::new(self.expr(0)?),
                }
            }
            "extract" => {
                let part = self.date_part(true)?;
                self.expect("from")?;
                Expr::Extract {
                    part,
                    timestamp: Box::new(self.expr(0)?),
                }
            }
            // The query's start, the same for every record.
            "utcnow" => Expr::Literal(Value::Timestamp(Timestamp::now())),
            _ => {
                let function = match name {
                    "to_string" => (Function::ToString, 2..=2),
                    "to_timestamp" => (Function::ToTimestamp, 1..=1),
                    "char_length" | "character_length" => (Function::CharLength, 1..=1),
                    "lower" => (Function::Lower, 1..=1),
                    "upper" => (Function::Upper, 1..=1),
                    "coalesce" => (Function::Coalesce, 1..=usize::MAX),
                    "nullif" => (Function::NullIf, 2..=2),
                    _ => return Err(unsupported_function(&name.to_ascii_uppercase())),
                };
                let mut args = Vec::new();
                if !self.at_sym(")") {
                    args.push(self.expr(0)?);
                    while self.eat_sym(",") {
                        args.push(self.expr(0)?);
                    }
                }
                if !function.1.contains(&args.len()) {
                    return Err(SelectError::new(
                        "IncorrectSqlFunctionArgumentType",
                        format!(
                            "{} takes a different number of arguments.",
                            name.to_ascii_uppercase()
                        ),
                    ));
                }
                Expr::Call(function.0, args)
            }
        };
        self.expect_sym(")")?;
        Ok(expr)
    }
}

fn describe(token: &Token) -> String {
    match token {
        Token::End => "the end of the expression".to_owned(),
        Token::Ident(s) => format!("'{s}'"),
        Token::Quoted(s) => format!("\"{s}\""),
        Token::Str(s) => format!("'{s}'"),
        Token::Int(i) => i.to_string(),
        Token::Float(f) => f.to_string(),
        Token::Timestamp(t) => format!("`{}`", t.to_text()),
        Token::Sym(s) => format!("'{s}'"),
    }
}

fn too_deep() -> SelectError {
    SelectError::new(
        "ParseUnsupportedSyntax",
        "The SQL expression nests too deeply.",
    )
}

fn unsupported_function(name: &str) -> SelectError {
    SelectError::new(
        "UnsupportedFunction",
        format!("The function {name} isn't supported."),
    )
}

fn expected_type(token: &Token) -> SelectError {
    SelectError::new(
        "ParseExpectedTypeName",
        format!(
            "The SQL expression expects a type (BOOL, INT, FLOAT, DECIMAL, STRING) to CAST to, not {}.",
            describe(token)
        ),
    )
}

/// Whether `expr` is deeper than `budget`, looking no deeper than that.
fn too_deep_at(expr: &Expr, budget: usize) -> bool {
    if budget == 0 {
        return true;
    }
    let deeper = |e: &Expr| too_deep_at(e, budget - 1);
    let deeper_opt = |e: &Option<Box<Expr>>| e.as_deref().is_some_and(deeper);
    match expr {
        Expr::Literal(_) | Expr::Path(_) | Expr::Aggregate(_) => false,
        Expr::Not(e) | Expr::Neg(e) | Expr::Cast(e, _) => deeper(e),
        Expr::Binary(_, a, b) => deeper(a) || deeper(b),
        Expr::Is { expr, .. } => deeper(expr),
        Expr::Like {
            expr,
            pattern,
            escape,
            ..
        } => deeper(expr) || deeper(pattern) || deeper_opt(escape),
        Expr::Between {
            expr, low, high, ..
        } => deeper(expr) || deeper(low) || deeper(high),
        Expr::In { expr, list, .. } => deeper(expr) || list.iter().any(deeper),
        Expr::Case {
            operand,
            whens,
            otherwise,
        } => {
            deeper_opt(operand)
                || whens.iter().any(|(w, t)| deeper(w) || deeper(t))
                || deeper_opt(otherwise)
        }
        Expr::Trim { chars, expr, .. } => deeper_opt(chars) || deeper(expr),
        Expr::Substring {
            expr,
            start,
            length,
        } => deeper(expr) || deeper(start) || deeper_opt(length),
        Expr::Call(_, args) => args.iter().any(deeper),
        Expr::DateAdd {
            quantity,
            timestamp,
            ..
        } => deeper(quantity) || deeper(timestamp),
        Expr::DateDiff { from, to, .. } => deeper(from) || deeper(to),
        Expr::Extract { timestamp, .. } => deeper(timestamp),
    }
}

impl Query {
    /// Every path the query reads the record by (its alias taken off),
    /// and whether it reads all of it (`*`, or the alias alone).
    pub fn paths(&self) -> (Vec<&[Step]>, bool) {
        let mut paths = Vec::new();
        let mut all = matches!(self.projection, Projection::Star);
        let items = match &self.projection {
            Projection::Star => &[][..],
            Projection::Items(items) => &items[..],
        };
        let exprs = items
            .iter()
            .map(|item| &item.expr)
            .chain(self.condition.iter())
            .chain(self.aggregates.iter().filter_map(|a| a.arg.as_ref()));
        for expr in exprs {
            expr.walk(&mut |e| {
                if let Expr::Path(steps) = e {
                    all |= steps.is_empty();
                    paths.push(&steps[..]);
                }
            });
        }
        (paths, all)
    }
}

impl Expr {
    /// Calls `f` on `self` and every expression in it.
    pub fn walk<'a>(&'a self, f: &mut dyn FnMut(&'a Expr)) {
        f(self);
        let mut each = |e: &'a Expr| e.walk(f);
        match self {
            Expr::Literal(_) | Expr::Path(_) | Expr::Aggregate(_) => {}
            Expr::Not(e) | Expr::Neg(e) | Expr::Cast(e, _) => each(e),
            Expr::Binary(_, a, b) => {
                each(a);
                each(b);
            }
            Expr::Is { expr, .. } => each(expr),
            Expr::Like {
                expr,
                pattern,
                escape,
                ..
            } => {
                each(expr);
                each(pattern);
                if let Some(e) = escape {
                    each(e);
                }
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                each(expr);
                each(low);
                each(high);
            }
            Expr::In { expr, list, .. } => {
                each(expr);
                list.iter().for_each(&mut each);
            }
            Expr::Case {
                operand,
                whens,
                otherwise,
            } => {
                if let Some(e) = operand {
                    each(e);
                }
                for (when, then) in whens {
                    each(when);
                    each(then);
                }
                if let Some(e) = otherwise {
                    each(e);
                }
            }
            Expr::Trim { chars, expr, .. } => {
                if let Some(e) = chars {
                    each(e);
                }
                each(expr);
            }
            Expr::Substring {
                expr,
                start,
                length,
            } => {
                each(expr);
                each(start);
                if let Some(e) = length {
                    each(e);
                }
            }
            Expr::Call(_, args) => args.iter().for_each(&mut each),
            Expr::DateAdd {
                quantity,
                timestamp,
                ..
            } => {
                each(quantity);
                each(timestamp);
            }
            Expr::DateDiff { from, to, .. } => {
                each(from);
                each(to);
            }
            Expr::Extract { timestamp, .. } => each(timestamp),
        }
    }
}

/// Whether `expr` reads the record other than through an aggregate.
fn reads_record(expr: &Expr) -> bool {
    match expr {
        Expr::Literal(_) | Expr::Aggregate(_) => false,
        Expr::Path(_) => true,
        Expr::Not(e) | Expr::Neg(e) | Expr::Cast(e, _) => reads_record(e),
        Expr::Binary(_, a, b) => reads_record(a) || reads_record(b),
        Expr::Is { expr, .. } => reads_record(expr),
        Expr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            reads_record(expr)
                || reads_record(pattern)
                || escape.as_deref().is_some_and(reads_record)
        }
        Expr::Between {
            expr, low, high, ..
        } => reads_record(expr) || reads_record(low) || reads_record(high),
        Expr::In { expr, list, .. } => reads_record(expr) || list.iter().any(reads_record),
        Expr::Case {
            operand,
            whens,
            otherwise,
        } => {
            operand.as_deref().is_some_and(reads_record)
                || whens
                    .iter()
                    .any(|(w, t)| reads_record(w) || reads_record(t))
                || otherwise.as_deref().is_some_and(reads_record)
        }
        Expr::Trim { chars, expr, .. } => {
            chars.as_deref().is_some_and(reads_record) || reads_record(expr)
        }
        Expr::Substring {
            expr,
            start,
            length,
        } => {
            reads_record(expr) || reads_record(start) || length.as_deref().is_some_and(reads_record)
        }
        Expr::Call(_, args) => args.iter().any(reads_record),
        Expr::DateAdd {
            quantity,
            timestamp,
            ..
        } => reads_record(quantity) || reads_record(timestamp),
        Expr::DateDiff { from, to, .. } => reads_record(from) || reads_record(to),
        Expr::Extract { timestamp, .. } => reads_record(timestamp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(query: &Query) -> Vec<&str> {
        match &query.projection {
            Projection::Star => vec!["*"],
            Projection::Items(items) => items.iter().map(|i| i.name.as_str()).collect(),
        }
    }

    #[test]
    fn parses_the_common_shapes() {
        let q = parse("select * from s3object").unwrap();
        assert!(matches!(q.projection, Projection::Star));
        let q = parse(
            "SELECT s._1, s.\"Name\" AS n, s.age + 1 FROM S3Object s WHERE s._3 > 30 LIMIT 5",
        )
        .unwrap();
        assert_eq!(names(&q), ["_1", "n", "_3"]);
        assert_eq!(q.limit, Some(5));
        let q = parse("SELECT COUNT(*), AVG(CAST(s.x AS INT)) FROM S3Object[*] AS s").unwrap();
        assert_eq!(q.aggregates.len(), 2);
        let q = parse("SELECT s.a.b[0] FROM S3Object s").unwrap();
        let Projection::Items(items) = &q.projection else {
            panic!()
        };
        assert!(matches!(&items[0].expr, Expr::Path(steps) if steps.len() == 3));
        assert_eq!(items[0].name, "_1");
    }

    #[test]
    fn the_alias_is_taken_off_paths() {
        let q = parse("SELECT s.name, name, S3Object.name FROM S3Object s").unwrap();
        let Projection::Items(items) = &q.projection else {
            panic!()
        };
        for item in items {
            assert!(matches!(&item.expr, Expr::Path(steps) if steps.len() == 1));
        }
    }

    #[test]
    fn refuses_what_it_does_not_take() {
        let code = |sql: &str| parse(sql).unwrap_err().code;
        assert_eq!(code("SELECT *"), "ParseSelectMissingFrom");
        assert_eq!(
            code("SELECT * FROM S3Object GROUP BY x"),
            "UnsupportedSyntax"
        );
        assert_eq!(
            code("SELECT s.a, COUNT(*) FROM S3Object s"),
            "ParseUnsupportedSyntax"
        );
        assert_eq!(
            code("SELECT * FROM S3Object WHERE COUNT(*) > 1"),
            "ParseUnsupportedSyntax"
        );
        assert_eq!(code("SELECT ABS(1) FROM S3Object"), "UnsupportedFunction");
        assert_eq!(
            code("SELECT *, a FROM S3Object"),
            "ParseAsteriskIsNotAloneInSelectList"
        );
        assert_eq!(code("SELECT a FROM S3Object[*].x"), "UnsupportedSyntax");
        assert_eq!(code("SELECT a FROM t"), "InvalidDataSource");
        assert_eq!(code("SELECT 'a FROM S3Object"), "LexerInvalidLiteral");
        assert_eq!(
            code("SELECT a FROM S3Object LIMIT -1"),
            "EvaluatorNegativeLimit"
        );
    }

    #[test]
    fn refuses_what_nests_too_deeply() {
        let deep = format!(
            "SELECT {}1{} FROM S3Object",
            "(".repeat(500),
            ")".repeat(500)
        );
        assert_eq!(parse(&deep).unwrap_err().code, "ParseUnsupportedSyntax");
        let long = format!("SELECT 1{} FROM S3Object", "+1".repeat(5000));
        assert_eq!(parse(&long).unwrap_err().code, "ParseUnsupportedSyntax");
        let deep_chain = format!("SELECT 1{} FROM S3Object", "+1".repeat(500));
        assert_eq!(
            parse(&deep_chain).unwrap_err().code,
            "ParseUnsupportedSyntax"
        );
        let wide = format!("SELECT {} FROM S3Object", vec!["a + 1"; 400].join(", "));
        assert!(parse(&wide).is_ok());
        let fine = format!("SELECT 1{} FROM S3Object", "+1".repeat(100));
        assert!(parse(&fine).is_ok());
    }
}
