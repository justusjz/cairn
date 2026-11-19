//! Which row groups a query's condition rules out by their columns'
//! statistics (each chunk's min and max), so that they aren't read.
//!
//! A row group is ruled out only if no row in it can make the condition
//! true: for a comparison of a top-level column with a literal (`=`, `<`,
//! `<=`, `>`, `>=`, `BETWEEN`, `IN`) whose value the column's min and max
//! leave out, or `IS NULL` of a column without nulls, and `AND`s and `OR`s
//! of such. Only where the column's values and the literal are of a kind
//! (numbers, strings, timestamps), and so compare as the query would compare
//! them: a string column's min and max say nothing of the numbers its
//! strings read as (`"10" < "9"`). Anything else may match.

use std::cmp::Ordering;

use parquet::{
    basic::{ConvertedType, LogicalType, TimeUnit, Type as PhysicalType},
    file::{metadata::RowGroupMetaData, statistics::Statistics},
    schema::types::{ColumnDescriptor, SchemaDescriptor},
};

use super::super::{
    sql::{BinOp, Expr, Step},
    timestamp::{Precision, Timestamp},
    value::{Value, compare},
};

/// What a column's values, and a literal, are, as comparisons go.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Kind {
    Number,
    Text,
    Time,
}

fn kind(value: &Value) -> Option<Kind> {
    match value {
        Value::Int(_) | Value::Float(_) => Some(Kind::Number),
        Value::Str(_) => Some(Kind::Text),
        Value::Timestamp(_) => Some(Kind::Time),
        _ => None,
    }
}

/// A column's min and max in a row group, and what kind they are.
struct Bounds {
    kind: Kind,
    min: Value,
    max: Value,
}

/// Whether some row of `group` may make `condition` true.
pub fn may_match(group: &RowGroupMetaData, schema: &SchemaDescriptor, condition: &Expr) -> bool {
    let column = |expr: &Expr| column(schema, expr);
    let stats = |i: usize| group.column(i).statistics();
    let bounds = |i: usize| stats(i).and_then(|s| bounds(&schema.column(i), s));
    match condition {
        Expr::Binary(BinOp::And, a, b) => {
            may_match(group, schema, a) && may_match(group, schema, b)
        }
        Expr::Binary(BinOp::Or, a, b) => may_match(group, schema, a) || may_match(group, schema, b),
        Expr::Binary(op @ (BinOp::Eq | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge), a, b) => {
            let (i, literal, op) = match (column(a), literal(b), column(b), literal(a)) {
                (Some(i), Some(literal), _, _) => (i, literal, *op),
                // `literal op column` is `column op' literal`.
                (_, _, Some(i), Some(literal)) => (i, literal, flip(*op)),
                _ => return true,
            };
            match bounds(i) {
                Some(b) if Some(b.kind) == kind(literal) => compares(op, &b, literal),
                _ => true,
            }
        }
        Expr::Between {
            expr,
            low,
            high,
            negated: false,
        } => match (column(expr), literal(low), literal(high)) {
            (Some(i), Some(low), Some(high)) => match bounds(i) {
                Some(b) if Some(b.kind) == kind(low) && Some(b.kind) == kind(high) => {
                    compares(BinOp::Ge, &b, low) && compares(BinOp::Le, &b, high)
                }
                _ => true,
            },
            _ => true,
        },
        Expr::In {
            expr,
            list,
            negated: false,
        } => {
            let Some(b) = column(expr).and_then(bounds) else {
                return true;
            };
            list.iter().any(|item| match literal(item) {
                Some(literal) if kind(literal) == Some(b.kind) => compares(BinOp::Eq, &b, literal),
                _ => true,
            })
        }
        // IS NULL of a column without nulls.
        Expr::Is {
            expr,
            missing: false,
            negated: false,
        } => match column(expr).and_then(stats) {
            Some(s) => s.null_count_opt() != Some(0),
            None => true,
        },
        _ => true,
    }
}

/// Whether some value from `b`'s min to its max may be `op literal`.
fn compares(op: BinOp, b: &Bounds, literal: &Value) -> bool {
    let (Some(min), Some(max)) = (compare(&b.min, literal), compare(&b.max, literal)) else {
        return true;
    };
    match op {
        BinOp::Eq => min != Ordering::Greater && max != Ordering::Less,
        BinOp::Lt => min == Ordering::Less,
        BinOp::Le => min != Ordering::Greater,
        BinOp::Gt => max == Ordering::Greater,
        BinOp::Ge => max != Ordering::Less,
        _ => true,
    }
}

fn flip(op: BinOp) -> BinOp {
    match op {
        BinOp::Lt => BinOp::Gt,
        BinOp::Le => BinOp::Ge,
        BinOp::Gt => BinOp::Lt,
        BinOp::Ge => BinOp::Le,
        op => op,
    }
}

fn literal(expr: &Expr) -> Option<&Value> {
    match expr {
        Expr::Literal(value) => Some(value),
        _ => None,
    }
}

/// The leaf column a path names, if it names a top-level one that is a
/// leaf: the first whose name it is, as reading the record finds it.
fn column(schema: &SchemaDescriptor, expr: &Expr) -> Option<usize> {
    let Expr::Path(steps) = expr else {
        return None;
    };
    let [Step::Field { name, quoted }] = &steps[..] else {
        return None;
    };
    let field = schema
        .root_schema()
        .get_fields()
        .iter()
        .find(|f| match quoted {
            true => f.name() == name,
            false => f.name().eq_ignore_ascii_case(name),
        })?;
    if !field.is_primitive() {
        return None;
    }
    (0..schema.num_columns()).find(|&i| {
        let column = schema.column(i);
        let parts = column.path().parts();
        parts.len() == 1 && parts[0] == field.name()
    })
}

/// A column's min and max in `stats`, as the values reading it gives (see
/// `value`), if they're of a kind that compares as its values do.
fn bounds(column: &ColumnDescriptor, stats: &Statistics) -> Option<Bounds> {
    let logical = column.logical_type_ref();
    // Unsigned integers' statistics may be in signed order.
    let unsigned = matches!(
        logical,
        Some(LogicalType::Integer {
            is_signed: false,
            ..
        })
    ) || matches!(
        column.converted_type(),
        ConvertedType::UINT_8
            | ConvertedType::UINT_16
            | ConvertedType::UINT_32
            | ConvertedType::UINT_64
    );
    if unsigned {
        return None;
    }
    let decimal = matches!(logical, Some(LogicalType::Decimal { .. }))
        || column.converted_type() == ConvertedType::DECIMAL;
    let scaled = |v: i64| Value::Float(v as f64 / 10f64.powi(column.type_scale()));
    let time = |nanos: i128, utc: bool| {
        Timestamp::from_unix(nanos, Precision::Fraction(9), utc)
            .ok()
            .map(Value::Timestamp)
    };
    let (kind, min, max) = match stats {
        Statistics::Int32(s) => {
            let (min, max) = (*s.min_opt()?, *s.max_opt()?);
            let date = matches!(logical, Some(LogicalType::Date))
                || column.converted_type() == ConvertedType::DATE;
            if date {
                let day = |d: i32| time(i128::from(d) * 86_400 * 1_000_000_000, true);
                (Kind::Time, day(min)?, day(max)?)
            } else if decimal {
                (Kind::Number, scaled(i64::from(min)), scaled(i64::from(max)))
            } else {
                (
                    Kind::Number,
                    Value::Int(i64::from(min)),
                    Value::Int(i64::from(max)),
                )
            }
        }
        Statistics::Int64(s) => {
            let (min, max) = (*s.min_opt()?, *s.max_opt()?);
            let unit = match logical {
                Some(LogicalType::Timestamp {
                    unit,
                    is_adjusted_to_u_t_c,
                }) => Some((*unit, *is_adjusted_to_u_t_c)),
                _ => match column.converted_type() {
                    ConvertedType::TIMESTAMP_MILLIS => Some((TimeUnit::MILLIS, true)),
                    ConvertedType::TIMESTAMP_MICROS => Some((TimeUnit::MICROS, true)),
                    _ => None,
                },
            };
            match unit {
                Some((unit, utc)) => {
                    let scale: i128 = match unit {
                        TimeUnit::MILLIS => 1_000_000,
                        TimeUnit::MICROS => 1_000,
                        TimeUnit::NANOS => 1,
                    };
                    let at = |v: i64| time(i128::from(v) * scale, utc);
                    (Kind::Time, at(min)?, at(max)?)
                }
                None if decimal => (Kind::Number, scaled(min), scaled(max)),
                None => (Kind::Number, Value::Int(min), Value::Int(max)),
            }
        }
        Statistics::Float(s) => {
            let (min, max) = (f64::from(*s.min_opt()?), f64::from(*s.max_opt()?));
            if min.is_nan() || max.is_nan() {
                return None;
            }
            (Kind::Number, Value::Float(min), Value::Float(max))
        }
        Statistics::Double(s) => {
            let (min, max) = (*s.min_opt()?, *s.max_opt()?);
            if min.is_nan() || max.is_nan() {
                return None;
            }
            (Kind::Number, Value::Float(min), Value::Float(max))
        }
        // Strings, in the byte order they compare in: not in the
        // deprecated min and max, which were signed.
        Statistics::ByteArray(s)
            if column.physical_type() == PhysicalType::BYTE_ARRAY && !decimal =>
        {
            if stats.is_min_max_deprecated() {
                return None;
            }
            let text = |b: &parquet::data_type::ByteArray| {
                std::str::from_utf8(b.data())
                    .ok()
                    .map(|t| Value::Str(t.to_owned()))
            };
            (Kind::Text, text(s.min_opt()?)?, text(s.max_opt()?)?)
        }
        _ => return None,
    };
    Some(Bounds { kind, min, max })
}
