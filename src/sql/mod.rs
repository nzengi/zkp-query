// SQL parser and compiler module
// Paper Section 3: Compiling SQL queries to ZKP circuit

use halo2_proofs::circuit::Value;
use std::collections::HashMap;

use crate::circuit::{AggregationOp, GroupByOp, JoinOp, RangeCheckOp, SortOp};

/// SQL Query AST (Abstract Syntax Tree)
/// Paper Section 3: Used to compile SQL queries to circuit
#[derive(Clone, Debug)]
pub struct SQLQuery {
    pub columns: Vec<String>,
    pub from: String,
    pub where_clause: Option<WhereClause>,
    pub group_by: Option<Vec<String>>,
    pub order_by: Option<Vec<OrderBy>>,
    pub having: Option<HavingClause>,
    pub joins: Option<Vec<JoinClause>>,
    pub aggregations: Option<Vec<AggregationClause>>,
}

/// WHERE clause
#[derive(Clone, Debug)]
pub enum WhereClause {
    /// Range check: column < value
    LessThan { column: String, value: u64 },
    /// Range check: column > value
    GreaterThan { column: String, value: u64 },
    /// Range check: column = value
    Equal { column: String, value: u64 },
    /// AND operation
    And(Box<WhereClause>, Box<WhereClause>),
    /// OR operation
    Or(Box<WhereClause>, Box<WhereClause>),
}

/// JOIN clause
#[derive(Clone, Debug)]
pub struct JoinClause {
    pub table: String,
    pub on: JoinCondition,
    pub join_type: JoinType,
}

/// JOIN condition
#[derive(Clone, Debug)]
pub struct JoinCondition {
    pub left_column: String,
    pub right_column: String,
}

/// JOIN type
#[derive(Clone, Debug)]
pub enum JoinType {
    Inner,
    Left,
    Right,
    Full,
}

/// ORDER BY clause
#[derive(Clone, Debug)]
pub struct OrderBy {
    pub column: String,
    pub direction: OrderDirection,
}

/// ORDER direction
#[derive(Clone, Debug)]
pub enum OrderDirection {
    Asc,
    Desc,
}

/// HAVING clause
#[derive(Clone, Debug)]
pub enum HavingClause {
    /// Aggregation result comparison
    Compare {
        aggregation: String,
        operator: ComparisonOp,
        value: u64,
    },
}

/// Comparison operator
#[derive(Clone, Debug)]
pub enum ComparisonOp {
    LessThan,
    GreaterThan,
    Equal,
}

/// Aggregation clause
#[derive(Clone, Debug)]
pub struct AggregationClause {
    pub function: AggregationFunction,
    pub column: String,
}

/// Aggregation function
#[derive(Clone, Debug)]
pub enum AggregationFunction {
    Sum,
    Count,
    Max,
    Min,
    Avg,
}

/// SQL Parser
/// Converts SQL strings to AST
pub struct SQLParser;

impl SQLParser {
    /// Parse SQL string
    /// Simple parser - production can use more advanced parser (e.g.: sqlparser-rs)
    pub fn parse(sql: &str) -> Result<SQLQuery, String> {
        let sql = sql.trim().to_lowercase();

        // Simple SELECT parsing
        if !sql.starts_with("select") {
            return Err("Only SELECT queries are supported".to_string());
        }

        // Parse SELECT ... FROM ... WHERE ... GROUP BY ... ORDER BY ... pattern
        let mut query = SQLQuery {
            columns: Vec::new(),
            from: String::new(),
            where_clause: None,
            group_by: None,
            order_by: None,
            having: None,
            joins: None,
            aggregations: None,
        };

        // Find FROM clause
        let from_idx = sql.find(" from ").ok_or("Missing FROM clause")?;
        let select_part = &sql[6..from_idx].trim();

        // Parse columns
        query.columns = select_part
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        // Parse after FROM
        let after_from = &sql[from_idx + 6..];

        // Find WHERE clause
        if let Some(where_idx) = after_from.find(" where ") {
            query.from = after_from[..where_idx].trim().to_string();
            let where_part = &after_from[where_idx + 7..];

            // Parse WHERE clause (simple: column < value, column > value, column = value)
            query.where_clause = Some(Self::parse_where_clause(where_part)?);
        } else {
            // If no WHERE, take part until GROUP BY or ORDER BY as FROM
            let end_idx = after_from
                .find(" group by ")
                .or_else(|| after_from.find(" order by "))
                .unwrap_or(after_from.len());
            query.from = after_from[..end_idx].trim().to_string();
        }

        // Find GROUP BY clause
        if let Some(group_idx) = after_from.find(" group by ") {
            let group_part = &after_from[group_idx + 10..];
            let end_idx = group_part
                .find(" order by ")
                .or_else(|| group_part.find(" having "))
                .unwrap_or(group_part.len());

            query.group_by = Some(
                group_part[..end_idx]
                    .trim()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
            );
        }

        // Find ORDER BY clause
        if let Some(order_idx) = after_from.find(" order by ") {
            let order_part = &after_from[order_idx + 10..];
            query.order_by = Some(Self::parse_order_by(order_part)?);
        }

        // Detect aggregation functions
        let mut aggregations = Vec::new();
        for col in &query.columns {
            if col.starts_with("sum(")
                || col.starts_with("count(")
                || col.starts_with("max(")
                || col.starts_with("min(")
            {
                if let Some(agg) = Self::parse_aggregation(col) {
                    aggregations.push(agg);
                }
            }
        }
        if !aggregations.is_empty() {
            query.aggregations = Some(aggregations);
        }

        Ok(query)
    }

    /// Parse WHERE clause
    fn parse_where_clause(where_part: &str) -> Result<WhereClause, String> {
        let where_part = where_part.trim();

        // Check AND/OR operators
        if let Some(and_idx) = where_part.find(" and ") {
            let left = Self::parse_where_clause(&where_part[..and_idx])?;
            let right = Self::parse_where_clause(&where_part[and_idx + 5..])?;
            return Ok(WhereClause::And(Box::new(left), Box::new(right)));
        }

        if let Some(or_idx) = where_part.find(" or ") {
            let left = Self::parse_where_clause(&where_part[..or_idx])?;
            let right = Self::parse_where_clause(&where_part[or_idx + 4..])?;
            return Ok(WhereClause::Or(Box::new(left), Box::new(right)));
        }

        // Simple comparison: column < value, column > value, column = value
        if let Some(lt_idx) = where_part.find(" < ") {
            let column = where_part[..lt_idx].trim().to_string();
            let value = where_part[lt_idx + 3..]
                .trim()
                .parse::<u64>()
                .map_err(|_| "Invalid number in WHERE clause")?;
            return Ok(WhereClause::LessThan { column, value });
        }

        if let Some(gt_idx) = where_part.find(" > ") {
            let column = where_part[..gt_idx].trim().to_string();
            let value = where_part[gt_idx + 3..]
                .trim()
                .parse::<u64>()
                .map_err(|_| "Invalid number in WHERE clause")?;
            return Ok(WhereClause::GreaterThan { column, value });
        }

        if let Some(eq_idx) = where_part.find(" = ") {
            let column = where_part[..eq_idx].trim().to_string();
            let value = where_part[eq_idx + 3..]
                .trim()
                .parse::<u64>()
                .map_err(|_| "Invalid number in WHERE clause")?;
            return Ok(WhereClause::Equal { column, value });
        }

        Err("Unsupported WHERE clause format".to_string())
    }

    /// Parse ORDER BY clause
    fn parse_order_by(order_part: &str) -> Result<Vec<OrderBy>, String> {
        let order_part = order_part.trim();
        let mut orders = Vec::new();

        for part in order_part.split(',') {
            let part = part.trim();
            if part.ends_with(" desc") {
                let column = part[..part.len() - 5].trim().to_string();
                orders.push(OrderBy {
                    column,
                    direction: OrderDirection::Desc,
                });
            } else if part.ends_with(" asc") {
                let column = part[..part.len() - 4].trim().to_string();
                orders.push(OrderBy {
                    column,
                    direction: OrderDirection::Asc,
                });
            } else {
                // Default: ASC
                orders.push(OrderBy {
                    column: part.to_string(),
                    direction: OrderDirection::Asc,
                });
            }
        }

        Ok(orders)
    }

    /// Parse aggregation function
    fn parse_aggregation(col: &str) -> Option<AggregationClause> {
        if col.starts_with("sum(") && col.ends_with(")") {
            let column = col[4..col.len() - 1].trim().to_string();
            Some(AggregationClause {
                function: AggregationFunction::Sum,
                column,
            })
        } else if col.starts_with("count(") && col.ends_with(")") {
            let column = col[6..col.len() - 1].trim().to_string();
            Some(AggregationClause {
                function: AggregationFunction::Count,
                column,
            })
        } else if col.starts_with("max(") && col.ends_with(")") {
            let column = col[4..col.len() - 1].trim().to_string();
            Some(AggregationClause {
                function: AggregationFunction::Max,
                column,
            })
        } else if col.starts_with("min(") && col.ends_with(")") {
            let column = col[4..col.len() - 1].trim().to_string();
            Some(AggregationClause {
                function: AggregationFunction::Min,
                column,
            })
        } else {
            None
        }
    }
}

/// SQL Compiler
/// Compiles SQL AST to circuit
pub struct SQLCompiler;

impl SQLCompiler {
    /// Compile SQL query to circuit
    /// Paper Section 3: Compiling SQL queries to ZKP circuit
    ///
    /// # Parameters
    ///
    /// - `query`: Parsed SQL query
    /// - `table_data`: Table data (column_name -> values mapping)
    ///
    /// # Returns
    ///
    /// Compiled query with circuit operations
    pub fn compile(
        query: &SQLQuery,
        table_data: &HashMap<String, HashMap<String, Vec<u64>>>,
    ) -> Result<CompiledQuery, String> {
        let mut compiled = CompiledQuery {
            range_checks: Vec::new(),
            sorts: Vec::new(),
            group_bys: Vec::new(),
            joins: Vec::new(),
            aggregations: Vec::new(),
        };

        // Convert WHERE clause to range check operations
        if let Some(where_clause) = &query.where_clause {
            Self::compile_where_clause(where_clause, table_data, &query.from, &mut compiled)?;
        }

        // Convert ORDER BY clause to sort operations
        if let Some(order_by) = &query.order_by {
            for order in order_by {
                let column_data = table_data
                    .get(&query.from)
                    .and_then(|t| t.get(&order.column))
                    .ok_or_else(|| {
                        format!("Column {} not found in table {}", order.column, query.from)
                    })?;

                let mut sorted = column_data.clone();
                match order.direction {
                    OrderDirection::Asc => sorted.sort(),
                    OrderDirection::Desc => {
                        sorted.sort();
                        sorted.reverse();
                    }
                }

                compiled.sorts.push(SortOp {
                    input: column_data.iter().map(|&v| Value::known(v)).collect(),
                    sorted_output: sorted,
                });
            }
        }

        // Convert GROUP BY clause to group_by operations
        if let Some(group_by_cols) = &query.group_by {
            for col in group_by_cols {
                let column_data = table_data
                    .get(&query.from)
                    .and_then(|t| t.get(col))
                    .ok_or_else(|| format!("Column {} not found in table {}", col, query.from))?;

                // Extract group keys (unique values)
                let mut group_keys: Vec<u64> = column_data.iter().copied().collect();
                group_keys.sort();
                group_keys.dedup();

                compiled.group_bys.push(GroupByOp { group_keys });
            }
        }

        // Compile aggregation operations
        if let Some(aggregations) = &query.aggregations {
            for agg in aggregations {
                let column_data = table_data
                    .get(&query.from)
                    .and_then(|t| t.get(&agg.column))
                    .ok_or_else(|| {
                        format!("Column {} not found in table {}", agg.column, query.from)
                    })?;

                // Get group keys (if GROUP BY exists)
                let group_keys = if let Some(group_by_cols) = &query.group_by {
                    // Use first group by column
                    if let Some(first_col) = group_by_cols.first() {
                        table_data
                            .get(&query.from)
                            .and_then(|t| t.get(first_col))
                            .map(|v| v.clone())
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };

                let agg_type = match agg.function {
                    AggregationFunction::Sum => "sum",
                    AggregationFunction::Count => "count",
                    AggregationFunction::Max => "max",
                    AggregationFunction::Min => "min",
                    AggregationFunction::Avg => "sum", // Use SUM for AVG, then divide by COUNT
                };

                compiled.aggregations.push(AggregationOp {
                    group_keys,
                    values: column_data.clone(),
                    agg_type: agg_type.to_string(),
                });
            }
        }

        // Compile JOIN operations
        if let Some(joins) = &query.joins {
            for join in joins {
                let left_table = table_data
                    .get(&query.from)
                    .ok_or_else(|| format!("Table {} not found", query.from))?;
                let right_table = table_data
                    .get(&join.table)
                    .ok_or_else(|| format!("Table {} not found", join.table))?;

                let left_keys = left_table
                    .get(&join.on.left_column)
                    .ok_or_else(|| {
                        format!(
                            "Column {} not found in table {}",
                            join.on.left_column, query.from
                        )
                    })?
                    .clone();
                let right_keys = right_table
                    .get(&join.on.right_column)
                    .ok_or_else(|| {
                        format!(
                            "Column {} not found in table {}",
                            join.on.right_column, join.table
                        )
                    })?
                    .clone();

                // Use first column for values (simple implementation)
                let left_values = left_table.values().next().cloned().unwrap_or_default();
                let right_values = right_table.values().next().cloned().unwrap_or_default();

                compiled.joins.push(JoinOp {
                    table1_keys: left_keys,
                    table1_values: left_values,
                    table2_keys: right_keys,
                    table2_values: right_values,
                });
            }
        }

        Ok(compiled)
    }

    /// Convert WHERE clause to range check operations
    fn compile_where_clause(
        where_clause: &WhereClause,
        table_data: &HashMap<String, HashMap<String, Vec<u64>>>,
        table_name: &str,
        compiled: &mut CompiledQuery,
    ) -> Result<(), String> {
        match where_clause {
            WhereClause::LessThan { column, value } => {
                let column_data = table_data
                    .get(table_name)
                    .and_then(|t| t.get(column))
                    .ok_or_else(|| {
                        format!("Column {} not found in table {}", column, table_name)
                    })?;

                for &val in column_data {
                    // Range check: val < value
                    // u value: value - val (if val < value)
                    let u = if val < *value { value - val } else { 0 };
                    compiled.range_checks.push(RangeCheckOp {
                        value: Value::known(val),
                        threshold: *value,
                        u,
                    });
                }
            }
            WhereClause::GreaterThan { column, value } => {
                let column_data = table_data
                    .get(table_name)
                    .and_then(|t| t.get(column))
                    .ok_or_else(|| {
                        format!("Column {} not found in table {}", column, table_name)
                    })?;

                for &val in column_data {
                    // For range check: val > value, can check val < MAX_VALUE - value
                    // Simple implementation: val >= value + 1 check
                    let threshold = value + 1;
                    let u = if val >= threshold { val - threshold } else { 0 };
                    compiled.range_checks.push(RangeCheckOp {
                        value: Value::known(val),
                        threshold,
                        u,
                    });
                }
            }
            WhereClause::Equal { column, value } => {
                let column_data = table_data
                    .get(table_name)
                    .and_then(|t| t.get(column))
                    .ok_or_else(|| {
                        format!("Column {} not found in table {}", column, table_name)
                    })?;

                for &val in column_data {
                    // Equality check: val == value
                    // Range check ile: val < value + 1 && val >= value
                    compiled.range_checks.push(RangeCheckOp {
                        value: Value::known(val),
                        threshold: value + 1,
                        u: if val < value + 1 {
                            (value + 1) - val
                        } else {
                            0
                        },
                    });
                }
            }
            WhereClause::And(left, right) => {
                Self::compile_where_clause(left, table_data, table_name, compiled)?;
                Self::compile_where_clause(right, table_data, table_name, compiled)?;
            }
            WhereClause::Or(left, right) => {
                // For OR: compile both conditions
                // (OR logic in circuit can be more complex, simple implementation)
                Self::compile_where_clause(left, table_data, table_name, compiled)?;
                Self::compile_where_clause(right, table_data, table_name, compiled)?;
            }
        }

        Ok(())
    }
}

/// Compiled SQL Query
/// SQL query compiled to circuit
#[derive(Clone, Debug)]
pub struct CompiledQuery {
    /// Range check operations
    pub range_checks: Vec<RangeCheckOp>,
    /// Sort operations
    pub sorts: Vec<SortOp>,
    /// Group-by operations
    pub group_bys: Vec<GroupByOp>,
    /// Join operations
    pub joins: Vec<JoinOp>,
    /// Aggregation operations
    pub aggregations: Vec<AggregationOp>,
}
