//! Evaluating a query's expressions against a record.

use std::cmp::Ordering;

use super::SelectError;
use super::sql::{Aggregate, AggregateKind, BinOp, Expr, Function, Step, Trim, Type};
use super::timestamp::Timestamp;
use super::value::{Number, Value, compare, parse_bool};

/// A record, as a query sees it.
pub enum Record<'a> {
    /// A CSV record's fields, and its header's names (`FileHeaderInfo`
    /// `USE`), if it has them.
    Csv {
        fields: &'a [String],
        header: Option<&'a [String]>,
    },
    Json(&'a Value),
}

impl Record<'_> {
    /// The whole record, as a value: a CSV record as a struct of its
    /// fields, by their header's names or else `_1`, `_2`, ...
    pub fn to_value(&self) -> Value {
        match self {
            Record::Json(value) => (*value).clone(),
            Record::Csv { fields, header } => Value::Struct(
                fields
                    .iter()
                    .enumerate()
                    .map(|(i, field)| (column_name(*header, i), Value::Str(field.clone())))
                    .collect(),
            ),
        }
    }

    /// Where `steps` lead in the record.
    fn lookup(&self, steps: &[Step]) -> Value {
        let Some((first, rest)) = steps.split_first() else {
            return self.to_value();
        };
        match self {
            Record::Json(value) => walk(value, steps),
            Record::Csv { fields, header } => {
                let field = match first {
                    Step::Field { name, quoted } => csv_column(fields, *header, name, *quoted),
                    Step::Index(i) => fields.get(*i).map(|f| Value::Str(f.clone())),
                };
                match field {
                    Some(value) if rest.is_empty() => value,
                    // A CSV field has nothing in it to go into.
                    _ => Value::Missing,
                }
            }
        }
    }
}

/// The `i`th (from 0) column's name.
pub fn column_name(header: Option<&[String]>, i: usize) -> String {
    match header.and_then(|h| h.get(i)) {
        Some(name) => name.clone(),
        None => format!("_{}", i + 1),
    }
}

/// A CSV record's column `name`: by its header, else by its position
/// (`_1` is the first).
fn csv_column(
    fields: &[String],
    header: Option<&[String]>,
    name: &str,
    quoted: bool,
) -> Option<Value> {
    if let Some(header) = header {
        let found = header.iter().position(|h| match quoted {
            true => h == name,
            false => h.eq_ignore_ascii_case(name),
        });
        if let Some(i) = found {
            return Some(
                fields
                    .get(i)
                    .map_or(Value::Missing, |f| Value::Str(f.clone())),
            );
        }
    }
    let n: usize = name.strip_prefix('_')?.parse().ok()?;
    Some(match n.checked_sub(1).and_then(|i| fields.get(i)) {
        Some(field) => Value::Str(field.clone()),
        None => Value::Missing,
    })
}

fn walk(value: &Value, steps: &[Step]) -> Value {
    let mut at = value;
    for step in steps {
        let next = match (step, at) {
            (Step::Field { name, quoted }, Value::Struct(fields)) => fields
                .iter()
                .find(|(key, _)| match quoted {
                    true => key == name,
                    false => key.eq_ignore_ascii_case(name),
                })
                .map(|(_, v)| v),
            (Step::Index(i), Value::List(items)) => items.get(*i),
            _ => None,
        };
        match next {
            Some(next) => at = next,
            None => return Value::Missing,
        }
    }
    at.clone()
}

/// Evaluates `expr` against `record`, with `aggregates`' results (for the
/// projection of a query with aggregates).
pub fn eval(expr: &Expr, record: &Record, aggregates: &[Value]) -> Result<Value, SelectError> {
    let eval = |e: &Expr| self::eval(e, record, aggregates);
    Ok(match expr {
        Expr::Literal(value) => value.clone(),
        Expr::Path(steps) => record.lookup(steps),
        Expr::Aggregate(i) => aggregates.get(*i).cloned().unwrap_or(Value::Null),
        Expr::Not(e) => match truth(&eval(e)?) {
            Some(b) => Value::Bool(!b),
            None => Value::Null,
        },
        Expr::Neg(e) => match eval(e)? {
            v if v.is_absent() => v,
            v => match v.as_number() {
                Some(Number::Int(i)) => match i.checked_neg() {
                    Some(i) => Value::Int(i),
                    None => return Err(overflow()),
                },
                Some(Number::Float(f)) => Value::Float(-f),
                None => return Err(not_a_number("-", &v)),
            },
        },
        Expr::Binary(BinOp::And, a, b) => {
            let a = truth(&eval(a)?);
            if a == Some(false) {
                return Ok(Value::Bool(false));
            }
            match (a, truth(&eval(b)?)) {
                (_, Some(false)) => Value::Bool(false),
                (Some(true), Some(true)) => Value::Bool(true),
                _ => Value::Null,
            }
        }
        Expr::Binary(BinOp::Or, a, b) => {
            let a = truth(&eval(a)?);
            if a == Some(true) {
                return Ok(Value::Bool(true));
            }
            match (a, truth(&eval(b)?)) {
                (_, Some(true)) => Value::Bool(true),
                (Some(false), Some(false)) => Value::Bool(false),
                _ => Value::Null,
            }
        }
        Expr::Binary(op, a, b) => binary(*op, eval(a)?, eval(b)?)?,
        Expr::Is {
            expr,
            missing,
            negated,
        } => {
            let value = eval(expr)?;
            let is = match missing {
                true => matches!(value, Value::Missing),
                // MISSING is NULL too, to IS NULL.
                false => value.is_absent(),
            };
            Value::Bool(is != *negated)
        }
        Expr::Like {
            expr,
            pattern,
            escape,
            negated,
        } => {
            let value = eval(expr)?;
            let pattern = eval(pattern)?;
            let escape = match escape {
                Some(e) => Some(eval(e)?),
                None => None,
            };
            if value.is_absent()
                || pattern.is_absent()
                || escape.as_ref().is_some_and(Value::is_absent)
            {
                return Ok(Value::Null);
            }
            let escape = match escape {
                None => None,
                Some(e) => {
                    let text = e.to_text();
                    let mut chars = text.chars();
                    match (chars.next(), chars.next()) {
                        (Some(c), None) => Some(c),
                        _ => {
                            return Err(SelectError::new(
                                "LikeInvalidInputs",
                                "LIKE's ESCAPE must be a single character.",
                            ));
                        }
                    }
                }
            };
            let matched = like(&value.to_text(), &pattern.to_text(), escape)?;
            Value::Bool(matched != *negated)
        }
        Expr::Between {
            expr,
            low,
            high,
            negated,
        } => {
            let value = eval(expr)?;
            let low = compare(&value, &eval(low)?);
            let high = compare(&value, &eval(high)?);
            match (low, high) {
                (Some(low), Some(high)) => {
                    let within = low != Ordering::Less && high != Ordering::Greater;
                    Value::Bool(within != *negated)
                }
                _ => Value::Null,
            }
        }
        Expr::In {
            expr,
            list,
            negated,
        } => {
            let value = eval(expr)?;
            if value.is_absent() {
                return Ok(Value::Null);
            }
            let mut unknown = false;
            for item in list {
                match compare(&value, &eval(item)?) {
                    Some(Ordering::Equal) => return Ok(Value::Bool(!*negated)),
                    Some(_) => {}
                    None => unknown = true,
                }
            }
            match unknown {
                true => Value::Null,
                false => Value::Bool(*negated),
            }
        }
        Expr::Case {
            operand,
            whens,
            otherwise,
        } => {
            let operand = match operand {
                Some(o) => Some(eval(o)?),
                None => None,
            };
            for (when, then) in whens {
                let when = eval(when)?;
                let hit = match &operand {
                    Some(operand) => compare(operand, &when) == Some(Ordering::Equal),
                    None => truth(&when) == Some(true),
                };
                if hit {
                    return eval(then);
                }
            }
            match otherwise {
                Some(e) => eval(e)?,
                None => Value::Null,
            }
        }
        Expr::Cast(e, ty) => cast(eval(e)?, *ty)?,
        Expr::Trim { side, chars, expr } => {
            let value = eval(expr)?;
            let chars = match chars {
                Some(c) => Some(eval(c)?),
                None => None,
            };
            if value.is_absent() || chars.as_ref().is_some_and(Value::is_absent) {
                return Ok(Value::Null);
            }
            let text = value.to_text();
            let set: Vec<char> = match &chars {
                Some(c) => c.to_text().chars().collect(),
                None => vec![' '],
            };
            let trimmed = match side {
                Trim::Leading => text.trim_start_matches(&set[..]),
                Trim::Trailing => text.trim_end_matches(&set[..]),
                Trim::Both => text.trim_matches(&set[..]),
            };
            Value::Str(trimmed.to_owned())
        }
        Expr::Substring {
            expr,
            start,
            length,
        } => {
            let value = eval(expr)?;
            let start = eval(start)?;
            let length = match length {
                Some(l) => Some(eval(l)?),
                None => None,
            };
            if value.is_absent()
                || start.is_absent()
                || length.as_ref().is_some_and(Value::is_absent)
            {
                return Ok(Value::Null);
            }
            let start = integer_argument("SUBSTRING", &start)?;
            let length = match length {
                Some(l) => Some(integer_argument("SUBSTRING", &l)?),
                None => None,
            };
            Value::Str(substring(&value.to_text(), start, length)?)
        }
        Expr::Call(function, args) => {
            let mut values = Vec::with_capacity(args.len());
            for arg in args {
                values.push(eval(arg)?);
            }
            match function {
                Function::ToString => {
                    let pattern = values.pop().unwrap_or(Value::Null);
                    let value = values.pop().unwrap_or(Value::Null);
                    if value.is_absent() || pattern.is_absent() {
                        return Ok(Value::Null);
                    }
                    let timestamp = timestamp_argument("TO_STRING", &value)?;
                    Value::Str(timestamp.format(&pattern.to_text())?)
                }
                Function::ToTimestamp => match values.pop().unwrap_or(Value::Null) {
                    value if value.is_absent() => Value::Null,
                    Value::Timestamp(t) => Value::Timestamp(t),
                    value => Value::Timestamp(Timestamp::parse(&value.to_text())?),
                },
                _ => call(*function, values),
            }
        }
        Expr::DateAdd {
            part,
            quantity,
            timestamp,
        } => {
            let quantity = eval(quantity)?;
            let value = eval(timestamp)?;
            if quantity.is_absent() || value.is_absent() {
                return Ok(Value::Null);
            }
            let quantity = integer_argument("DATE_ADD", &quantity)?;
            let timestamp = timestamp_argument("DATE_ADD", &value)?;
            Value::Timestamp(timestamp.add(*part, quantity)?)
        }
        Expr::DateDiff { part, from, to } => {
            let (from, to) = (eval(from)?, eval(to)?);
            if from.is_absent() || to.is_absent() {
                return Ok(Value::Null);
            }
            let from = timestamp_argument("DATE_DIFF", &from)?;
            let to = timestamp_argument("DATE_DIFF", &to)?;
            Value::Int(from.diff(*part, &to))
        }
        Expr::Extract { part, timestamp } => match eval(timestamp)? {
            value if value.is_absent() => Value::Null,
            value => Value::Int(timestamp_argument("EXTRACT", &value)?.extract(*part)),
        },
    })
}

/// A function's timestamp argument: a timestamp, or a string that is one
/// (CSV and JSON have their timestamps as strings).
fn timestamp_argument(function: &str, value: &Value) -> Result<Timestamp, SelectError> {
    let timestamp = match value {
        Value::Timestamp(t) => Some(*t),
        Value::Str(s) => Timestamp::parse(s).ok(),
        _ => None,
    };
    timestamp.ok_or_else(|| {
        SelectError::new(
            "IncorrectSqlFunctionArgumentType",
            format!("{function} expects a timestamp, not {}.", describe(value)),
        )
    })
}

/// Whether a value counts as true, false, or neither (`NULL`, and what
/// isn't a boolean).
pub fn truth(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::Str(s) => parse_bool(s),
        _ => None,
    }
}

fn overflow() -> SelectError {
    SelectError::new("IntegerOverflow", "An integer overflowed.")
}

fn not_a_number(op: &str, value: &Value) -> SelectError {
    SelectError::new(
        "InvalidDataType",
        format!("{op} expects a number, and {} isn't one.", describe(value)),
    )
}

fn describe(value: &Value) -> String {
    match value {
        Value::Str(s) => format!("'{}'", s.chars().take(64).collect::<String>()),
        Value::List(_) => "a list".to_owned(),
        Value::Struct(_) => "a struct".to_owned(),
        other => other.to_text(),
    }
}

fn binary(op: BinOp, a: Value, b: Value) -> Result<Value, SelectError> {
    let ordering = |test: fn(Ordering) -> bool| match compare(&a, &b) {
        Some(o) => Value::Bool(test(o)),
        None => Value::Null,
    };
    Ok(match op {
        BinOp::Eq => ordering(|o| o == Ordering::Equal),
        BinOp::Ne => ordering(|o| o != Ordering::Equal),
        BinOp::Lt => ordering(|o| o == Ordering::Less),
        BinOp::Le => ordering(|o| o != Ordering::Greater),
        BinOp::Gt => ordering(|o| o == Ordering::Greater),
        BinOp::Ge => ordering(|o| o != Ordering::Less),
        _ if a.is_absent() || b.is_absent() => Value::Null,
        BinOp::Concat => Value::Str(a.to_text() + &b.to_text()),
        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
            let symbol = match op {
                BinOp::Add => "+",
                BinOp::Sub => "-",
                BinOp::Mul => "*",
                BinOp::Div => "/",
                _ => "%",
            };
            let x = a.as_number().ok_or_else(|| not_a_number(symbol, &a))?;
            let y = b.as_number().ok_or_else(|| not_a_number(symbol, &b))?;
            arithmetic(op, x, y)?
        }
        BinOp::And | BinOp::Or => unreachable!("evaluated lazily"),
    })
}

fn arithmetic(op: BinOp, x: Number, y: Number) -> Result<Value, SelectError> {
    let by_zero = || SelectError::new("EvaluatorInvalidArguments", "Division by zero.");
    Ok(match (x, y) {
        (Number::Int(x), Number::Int(y)) => {
            let result = match op {
                BinOp::Add => x.checked_add(y),
                BinOp::Sub => x.checked_sub(y),
                BinOp::Mul => x.checked_mul(y),
                BinOp::Div if y == 0 => return Err(by_zero()),
                BinOp::Div => x.checked_div(y),
                BinOp::Mod if y == 0 => return Err(by_zero()),
                _ => x.checked_rem(y),
            };
            Value::Int(result.ok_or_else(overflow)?)
        }
        (x, y) => {
            let (x, y) = (x.as_f64(), y.as_f64());
            Value::Float(match op {
                BinOp::Add => x + y,
                BinOp::Sub => x - y,
                BinOp::Mul => x * y,
                BinOp::Div if y == 0.0 => return Err(by_zero()),
                BinOp::Div => x / y,
                BinOp::Mod if y == 0.0 => return Err(by_zero()),
                _ => x % y,
            })
        }
    })
}

fn cast(value: Value, ty: Type) -> Result<Value, SelectError> {
    if value.is_absent() {
        return Ok(value);
    }
    let failed = |value: &Value| {
        let name = match ty {
            Type::Bool => "BOOL",
            Type::Int => "INT",
            Type::Float => "FLOAT",
            Type::String => "STRING",
            Type::Timestamp => "TIMESTAMP",
        };
        SelectError::new(
            "CastFailed",
            format!("{} can't be cast to {name}.", describe(value)),
        )
    };
    Ok(match ty {
        Type::String => Value::Str(value.to_text()),
        Type::Timestamp => match &value {
            Value::Timestamp(t) => Value::Timestamp(*t),
            Value::Str(s) => Value::Timestamp(Timestamp::parse(s).map_err(|_| failed(&value))?),
            _ => return Err(failed(&value)),
        },
        Type::Bool => match &value {
            Value::Bool(b) => Value::Bool(*b),
            Value::Int(i) => Value::Bool(*i != 0),
            Value::Float(f) => Value::Bool(*f != 0.0),
            Value::Str(s) => Value::Bool(parse_bool(s).ok_or_else(|| failed(&value))?),
            _ => return Err(failed(&value)),
        },
        Type::Int => match &value {
            Value::Bool(b) => Value::Int(i64::from(*b)),
            Value::List(_) | Value::Struct(_) => return Err(failed(&value)),
            _ => match value.as_number() {
                Some(Number::Int(i)) => Value::Int(i),
                // Truncated, as SQL casts them.
                Some(Number::Float(f)) if f.is_finite() && f.abs() < 9.2e18 => {
                    Value::Int(f.trunc() as i64)
                }
                _ => return Err(failed(&value)),
            },
        },
        Type::Float => match &value {
            Value::Bool(b) => Value::Float(if *b { 1.0 } else { 0.0 }),
            Value::List(_) | Value::Struct(_) => return Err(failed(&value)),
            _ => match value.as_number() {
                Some(n) => Value::Float(n.as_f64()),
                None => return Err(failed(&value)),
            },
        },
    })
}

fn integer_argument(function: &str, value: &Value) -> Result<i64, SelectError> {
    match value.as_number() {
        Some(Number::Int(i)) => Ok(i),
        Some(Number::Float(f)) if f.fract() == 0.0 && f.abs() < 9.2e18 => Ok(f as i64),
        _ => Err(SelectError::new(
            "IncorrectSqlFunctionArgumentType",
            format!("{function} expects an integer, not {}.", describe(value)),
        )),
    }
}

/// SQL's SUBSTRING: from the `start`th character (from 1; before the
/// first counts towards `length`), `length` of them, or to the end.
fn substring(text: &str, start: i64, length: Option<i64>) -> Result<String, SelectError> {
    let end = match length {
        Some(l) if l < 0 => {
            return Err(SelectError::new(
                "IllegalSqlFunctionArgument",
                "SUBSTRING's length can't be negative.",
            ));
        }
        Some(l) => start.saturating_add(l),
        None => i64::MAX,
    };
    let from = start.max(1);
    if end <= from {
        return Ok(String::new());
    }
    Ok(text
        .chars()
        .skip((from - 1) as usize)
        .take((end - from) as usize)
        .collect())
}

fn call(function: Function, mut args: Vec<Value>) -> Value {
    match function {
        Function::Coalesce => args
            .into_iter()
            .find(|v| !v.is_absent())
            .unwrap_or(Value::Null),
        Function::NullIf => {
            let b = args.pop().unwrap_or(Value::Null);
            let a = args.pop().unwrap_or(Value::Null);
            match compare(&a, &b) {
                Some(Ordering::Equal) => Value::Null,
                _ => a,
            }
        }
        _ => {
            let value = args.pop().unwrap_or(Value::Null);
            if value.is_absent() {
                return Value::Null;
            }
            let text = value.to_text();
            match function {
                Function::CharLength => Value::Int(text.chars().count() as i64),
                Function::Lower => Value::Str(text.to_lowercase()),
                _ => Value::Str(text.to_uppercase()),
            }
        }
    }
}

/// Whether `text` matches the LIKE `pattern`: `%` any characters, `_` any
/// one, `escape` before either taking it as itself.
fn like(text: &str, pattern: &str, escape: Option<char>) -> Result<bool, SelectError> {
    #[derive(PartialEq)]
    enum Part {
        Any,
        One,
        Char(char),
    }
    let mut parts = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        parts.push(match c {
            c if Some(c) == escape => match chars.next() {
                Some(next) => Part::Char(next),
                None => {
                    return Err(SelectError::new(
                        "LikeInvalidInputs",
                        "LIKE's pattern ends with its escape character.",
                    ));
                }
            },
            '%' => Part::Any,
            '_' => Part::One,
            c => Part::Char(c),
        });
    }
    // The usual linear-backtracking wildcard match: on a mismatch, the last
    // `%` takes one more character.
    let text: Vec<char> = text.chars().collect();
    let (mut t, mut p) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    while t < text.len() {
        match parts.get(p) {
            Some(Part::Any) => {
                back = Some((p, t));
                p += 1;
            }
            Some(Part::One) => {
                t += 1;
                p += 1;
            }
            Some(Part::Char(c)) if *c == text[t] => {
                t += 1;
                p += 1;
            }
            _ => match back {
                Some((bp, bt)) => {
                    p = bp + 1;
                    t = bt + 1;
                    back = Some((bp, bt + 1));
                }
                None => return Ok(false),
            },
        }
    }
    Ok(parts[p..].iter().all(|part| *part == Part::Any))
}

/// An aggregate's running state.
pub enum Accumulator {
    Count(i64),
    Sum(Option<Number>),
    Avg { sum: f64, count: i64 },
    Extreme(Option<Value>),
}

impl Accumulator {
    pub fn new(aggregate: &Aggregate) -> Accumulator {
        match aggregate.kind {
            AggregateKind::Count => Accumulator::Count(0),
            AggregateKind::Sum => Accumulator::Sum(None),
            AggregateKind::Avg => Accumulator::Avg { sum: 0.0, count: 0 },
            AggregateKind::Min | AggregateKind::Max => Accumulator::Extreme(None),
        }
    }

    /// Takes `record` into account.
    pub fn add(&mut self, aggregate: &Aggregate, record: &Record) -> Result<(), SelectError> {
        let value = match &aggregate.arg {
            None => Value::Bool(true),
            Some(arg) => eval(arg, record, &[])?,
        };
        if value.is_absent() {
            return Ok(());
        }
        let number = |name: &str| {
            value.as_number().ok_or_else(|| {
                SelectError::new(
                    "IncorrectSqlFunctionArgumentType",
                    format!(
                        "{name} expects numbers, and {} isn't one.",
                        describe(&value)
                    ),
                )
            })
        };
        match self {
            Accumulator::Count(n) => *n += 1,
            Accumulator::Sum(sum) => {
                let n = number("SUM")?;
                *sum = Some(match (*sum, n) {
                    (None, n) => n,
                    (Some(Number::Int(a)), Number::Int(b)) => match a.checked_add(b) {
                        Some(s) => Number::Int(s),
                        None => return Err(overflow()),
                    },
                    (Some(a), b) => Number::Float(a.as_f64() + b.as_f64()),
                });
            }
            Accumulator::Avg { sum, count } => {
                *sum += number("AVG")?.as_f64();
                *count += 1;
            }
            Accumulator::Extreme(best) => {
                let replaces = match best {
                    None => true,
                    Some(best) => {
                        let order = compare(&value, best).ok_or_else(|| {
                            SelectError::new(
                                "IncorrectSqlFunctionArgumentType",
                                format!(
                                    "{} can't compare {} with {}.",
                                    if aggregate.kind == AggregateKind::Min {
                                        "MIN"
                                    } else {
                                        "MAX"
                                    },
                                    describe(&value),
                                    describe(best)
                                ),
                            )
                        })?;
                        match aggregate.kind {
                            AggregateKind::Min => order == Ordering::Less,
                            _ => order == Ordering::Greater,
                        }
                    }
                };
                if replaces {
                    *best = Some(value);
                }
            }
        }
        Ok(())
    }

    pub fn result(self) -> Value {
        match self {
            Accumulator::Count(n) => Value::Int(n),
            Accumulator::Sum(sum) => sum.map_or(Value::Null, Number::value),
            Accumulator::Avg { count: 0, .. } => Value::Null,
            Accumulator::Avg { sum, count } => Value::Float(sum / count as f64),
            Accumulator::Extreme(best) => best.unwrap_or(Value::Null),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::sql::{Projection, parse};
    use super::super::value::format_float;
    use super::*;

    /// The first selected item of `sql`, evaluated against the CSV record
    /// `fields` with the header `a,b,c`.
    fn first(sql: &str, fields: &[&str]) -> Result<String, SelectError> {
        let query = parse(sql)?;
        let Projection::Items(items) = &query.projection else {
            panic!()
        };
        let fields: Vec<String> = fields.iter().map(|f| f.to_string()).collect();
        let header: Vec<String> = ["a", "b", "c"].iter().map(|f| f.to_string()).collect();
        let record = Record::Csv {
            fields: &fields,
            header: Some(&header),
        };
        let value = eval(&items[0].expr, &record, &[])?;
        Ok(match value {
            Value::Missing => "MISSING".to_owned(),
            Value::Null => "NULL".to_owned(),
            Value::Str(s) => format!("'{s}'"),
            other => other.to_text(),
        })
    }

    #[test]
    fn evaluates() {
        let r = ["1", "Hello", "2.5"];
        let cases = [
            ("SELECT s.a + 1 FROM S3Object s", "2"),
            ("SELECT s.a + s.c FROM S3Object s", "3.5"),
            ("SELECT s._2 FROM S3Object s", "'Hello'"),
            ("SELECT \"B\" FROM S3Object s", "MISSING"),
            ("SELECT B FROM S3Object s", "'Hello'"),
            ("SELECT s._9 FROM S3Object s", "MISSING"),
            ("SELECT s.b || '!' FROM S3Object s", "'Hello!'"),
            ("SELECT 7 / 2 FROM S3Object", "3"),
            ("SELECT 7 % 3 FROM S3Object", "1"),
            ("SELECT 7.0 / 2 FROM S3Object", "3.5"),
            ("SELECT s.a = 1 AND s.b LIKE 'H%o' FROM S3Object s", "true"),
            ("SELECT s.b LIKE 'h%' FROM S3Object s", "false"),
            ("SELECT 'a_c' LIKE 'a!_c' ESCAPE '!' FROM S3Object", "true"),
            ("SELECT 'abc' LIKE 'a!_c' ESCAPE '!' FROM S3Object", "false"),
            ("SELECT 'xaaab' LIKE '%a%b' FROM S3Object", "true"),
            ("SELECT s.c BETWEEN 2 AND 3 FROM S3Object s", "true"),
            ("SELECT s.a IN (3, 2, 1) FROM S3Object s", "true"),
            ("SELECT s.a NOT IN (3, 2) FROM S3Object s", "true"),
            ("SELECT s.z IS MISSING FROM S3Object s", "true"),
            ("SELECT s.z IS NULL FROM S3Object s", "true"),
            ("SELECT s.a IS NOT NULL FROM S3Object s", "true"),
            ("SELECT NULL = 1 FROM S3Object", "NULL"),
            ("SELECT NULL AND FALSE FROM S3Object", "false"),
            ("SELECT NULL OR TRUE FROM S3Object", "true"),
            ("SELECT NOT (1 < 2) FROM S3Object", "false"),
            ("SELECT CAST(s.c AS INT) FROM S3Object s", "2"),
            ("SELECT CAST(s.a AS FLOAT) FROM S3Object s", "1.0"),
            ("SELECT CAST(s.a AS DECIMAL(10, 2)) FROM S3Object s", "1.0"),
            ("SELECT CAST('TRUE' AS BOOL) FROM S3Object", "true"),
            ("SELECT CAST(12 AS STRING) FROM S3Object", "'12'"),
            ("SELECT CHAR_LENGTH(s.b) FROM S3Object s", "5"),
            ("SELECT UPPER(s.b) FROM S3Object s", "'HELLO'"),
            ("SELECT lower(s.b) FROM S3Object s", "'hello'"),
            ("SELECT TRIM('  x  ') FROM S3Object", "'x'"),
            ("SELECT TRIM(LEADING FROM '  x  ') FROM S3Object", "'x  '"),
            (
                "SELECT TRIM(TRAILING 'yx' FROM 'axyxy') FROM S3Object",
                "'a'",
            ),
            (
                "SELECT SUBSTRING('123456789', 0) FROM S3Object",
                "'123456789'",
            ),
            (
                "SELECT SUBSTRING('123456789', 1) FROM S3Object",
                "'123456789'",
            ),
            (
                "SELECT SUBSTRING('123456789', 2) FROM S3Object",
                "'23456789'",
            ),
            (
                "SELECT SUBSTRING('123456789' FROM 2 FOR 3) FROM S3Object",
                "'234'",
            ),
            ("SELECT SUBSTRING('123456789', -4, 6) FROM S3Object", "'1'"),
            ("SELECT COALESCE(s.z, NULL, s.b) FROM S3Object s", "'Hello'"),
            ("SELECT NULLIF(s.a, 1) FROM S3Object s", "NULL"),
            ("SELECT NULLIF(s.a, 2) FROM S3Object s", "'1'"),
            (
                "SELECT CASE s.a WHEN '2' THEN 'two' WHEN '1' THEN 'one' END FROM S3Object s",
                "'one'",
            ),
            (
                "SELECT CASE WHEN s.a > 5 THEN 'big' ELSE 'small' END FROM S3Object s",
                "'small'",
            ),
            ("SELECT -s.a FROM S3Object s", "-1"),
        ];
        for (sql, want) in cases {
            assert_eq!(first(sql, &r).unwrap(), want, "{sql}");
        }
    }

    /// The date and time functions, as AWS's examples have them, and on
    /// CSV's strings.
    #[test]
    fn evaluates_timestamps() {
        let r = ["2017-01-02T03:04:05+07:08", "Hello", "2.5"];
        let cases = [
            (
                "SELECT DATE_ADD(year, 5, `2010-01-01T`) FROM S3Object",
                "2015-01-01T",
            ),
            (
                "SELECT DATE_ADD(hour, 1, `2017T`) FROM S3Object",
                "2017-01-01T01:00-00:00",
            ),
            (
                "SELECT DATE_ADD(MONTH, '13', `2010T`) FROM S3Object",
                "2011-02T",
            ),
            (
                "SELECT DATE_DIFF(month, `2011T`, `2010T`) FROM S3Object",
                "-12",
            ),
            (
                "SELECT DATE_DIFF(day, `2010-01-01T23:00`, `2010-01-02T01:00`) FROM S3Object",
                "0",
            ),
            (
                "SELECT EXTRACT(TIMEZONE_MINUTE FROM s.a) FROM S3Object s",
                "8",
            ),
            (
                "SELECT EXTRACT(hour FROM TO_TIMESTAMP(s.a)) FROM S3Object s",
                "3",
            ),
            (
                "SELECT TO_STRING(`1969-07-20T20:18Z`, 'MMMM d, y h:m a') FROM S3Object",
                "'July 20, 1969 8:18 PM'",
            ),
            ("SELECT TO_STRING(s.a, 'yyyy') FROM S3Object s", "'2017'"),
            (
                "SELECT TO_TIMESTAMP('2007-02-23T12:14:33.079-08:00') FROM S3Object",
                "2007-02-23T12:14:33.079-08:00",
            ),
            (
                "SELECT CAST('2007-04-05T14:30Z' AS TIMESTAMP) FROM S3Object",
                "2007-04-05T14:30Z",
            ),
            ("SELECT CAST(`2007T` AS STRING) FROM S3Object", "'2007T'"),
            ("SELECT s.a > `2017-01-01T` FROM S3Object s", "true"),
            (
                "SELECT `2017-01-02T03:04Z` = `2017-01-02T04:04+01:00` FROM S3Object",
                "true",
            ),
            (
                "SELECT s.a BETWEEN `2017T` AND `2018T` FROM S3Object s",
                "true",
            ),
            ("SELECT DATE_ADD(day, 1, NULL) FROM S3Object", "NULL"),
            ("SELECT EXTRACT(year FROM s.z) FROM S3Object s", "NULL"),
        ];
        for (sql, want) in cases {
            assert_eq!(first(sql, &r).unwrap(), want, "{sql}");
        }
        assert!(
            first("SELECT UTCNOW() FROM S3Object", &r)
                .unwrap()
                .ends_with('Z')
        );
        let code = |sql| first(sql, &r).unwrap_err().code;
        assert_eq!(
            code("SELECT CAST(s.b AS TIMESTAMP) FROM S3Object s"),
            "CastFailed"
        );
        assert_eq!(
            code("SELECT TO_TIMESTAMP(s.b) FROM S3Object s"),
            "CastFailed"
        );
        assert_eq!(
            code("SELECT EXTRACT(year FROM s.b) FROM S3Object s"),
            "IncorrectSqlFunctionArgumentType"
        );
        assert_eq!(
            code("SELECT DATE_ADD(day, 1.5, `2010T`) FROM S3Object"),
            "IncorrectSqlFunctionArgumentType"
        );
        assert_eq!(
            code("SELECT DATE_ADD(year, 10000, `2010T`) FROM S3Object"),
            "EvaluatorInvalidArguments"
        );
        assert_eq!(
            code("SELECT DATE_ADD(week, 1, `2010T`) FROM S3Object"),
            "ParseExpectedDatePart"
        );
        assert_eq!(
            code("SELECT DATE_DIFF(timezone_hour, `2010T`, `2011T`) FROM S3Object"),
            "ParseExpectedDatePart"
        );
        assert_eq!(
            code("SELECT `2010-13T` FROM S3Object"),
            "LexerInvalidLiteral"
        );
        assert_eq!(
            code("SELECT TO_STRING(`2010T`, 'Q') FROM S3Object"),
            "EvaluatorInvalidTimestampFormatPatternSymbol"
        );
    }

    #[test]
    fn fails_where_s3_select_does() {
        let r = ["x", "y", "z"];
        let code = |sql| first(sql, &r).unwrap_err().code;
        assert_eq!(
            code("SELECT CAST(s.a AS INT) FROM S3Object s"),
            "CastFailed"
        );
        assert_eq!(code("SELECT s.a + 1 FROM S3Object s"), "InvalidDataType");
        assert_eq!(
            code("SELECT 1 / 0 FROM S3Object s"),
            "EvaluatorInvalidArguments"
        );
        assert_eq!(
            code("SELECT 9223372036854775807 + 1 FROM S3Object"),
            "IntegerOverflow"
        );
    }

    #[test]
    fn json_paths() {
        let value: Value =
            serde_json::from_str(r#"{"Name":"x","tags":["a","b"],"addr":{"city":"Berlin"}}"#)
                .unwrap();
        let record = Record::Json(&value);
        let get = |sql: &str| {
            let query = parse(sql).unwrap();
            let Projection::Items(items) = &query.projection else {
                panic!()
            };
            eval(&items[0].expr, &record, &[]).unwrap().to_text()
        };
        assert_eq!(get("SELECT s.name FROM S3Object s"), "x");
        assert_eq!(get("SELECT s.\"name\" FROM S3Object s"), "");
        assert_eq!(get("SELECT s.tags[1] FROM S3Object s"), "b");
        assert_eq!(get("SELECT s.addr.city FROM S3Object s"), "Berlin");
        assert_eq!(get("SELECT s.addr['city'] FROM S3Object s"), "Berlin");
        assert_eq!(get("SELECT s.tags FROM S3Object s"), r#"["a","b"]"#);
    }

    #[test]
    fn floats_print_as_floats() {
        assert_eq!(format_float(2.0), "2.0");
    }
}
