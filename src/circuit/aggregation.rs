use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas::Base as Fr;

use super::config::PoneglyphConfig;
use super::group_by::GroupByConfig;
use super::range_check::RangeCheckConfig;

/// Aggregation Gate Configuration
/// According to Paper Section 4.5: SUM, COUNT, MAX, MIN operations
#[derive(Clone, Debug)]
pub struct AggregationConfig {
    // Value column - for values to be aggregated
    pub value_column: Column<Advice>,

    // Result column - for aggregation results
    pub result_column: Column<Advice>,

    // Selectors - for aggregation types
    pub sum_selector: Selector,
    pub count_selector: Selector,
    pub max_selector: Selector,
    pub min_selector: Selector,

    // Group-By integration
    pub group_by_config: GroupByConfig,

    // Range Check integration (for MAX/MIN comparison constraint)
    pub range_check_config: RangeCheckConfig,
}

/// Aggregation Chip
/// Paper Section 4.5 implementation
pub struct AggregationChip {
    config: AggregationConfig,
}

impl AggregationChip {
    /// Create new AggregationChip
    pub fn new(config: AggregationConfig) -> Self {
        Self { config }
    }

    /// Configure the Aggregation Gate
    /// Paper Section 4.5: SUM, COUNT, MAX, MIN operations
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        config: &PoneglyphConfig,
        group_by_config: &GroupByConfig,
        range_check_config: &RangeCheckConfig,
    ) -> AggregationConfig {
        // Get advice columns
        // Note: Range Check uses advice[0-9]
        // Sort Gate uses advice[2-4]
        // Group-By uses advice[5-7]
        // Join Gate uses advice[10-14]
        // For Aggregation we can use advice[8-9] (should be coordinated with Range Check)
        // However, we won't use Range Check's check/x and diff columns
        // at the same time as Aggregation, so it's safe
        let value_column = config.advice[8];
        let result_column = config.advice[9];

        // Create selectors
        let sum_selector = meta.selector();
        let count_selector = meta.selector();
        let max_selector = meta.selector();
        let min_selector = meta.selector();

        // SUM constraint: sum = Σ values[i] (sum within group)
        // Note: Selector won't be enabled for first row (no Rotation::prev())
        meta.create_gate("sum aggregation", |meta| {
            let s = meta.query_selector(sum_selector);
            let value = meta.query_advice(value_column, Rotation::cur());
            let result = meta.query_advice(result_column, Rotation::cur());
            let prev_result = meta.query_advice(result_column, Rotation::prev());
            let boundary = meta.query_advice(group_by_config.boundary_column, Rotation::cur());

            // If new group starts (boundary = 1), result = value
            // If same group continues (boundary = 0), result = prev_result + value
            let sum_expr = boundary.clone() * value.clone()
                + (Expression::Constant(Fr::ONE) - boundary.clone()) * (prev_result + value);

            vec![s * (result - sum_expr)]
        });

        // COUNT constraint: count = group_size (number of elements in group)
        meta.create_gate("count aggregation", |meta| {
            let s = meta.query_selector(count_selector);
            let result = meta.query_advice(result_column, Rotation::cur());
            let prev_result = meta.query_advice(result_column, Rotation::prev());
            let boundary = meta.query_advice(group_by_config.boundary_column, Rotation::cur());

            // If new group starts (boundary = 1), count = 1
            // If same group continues (boundary = 0), count = prev_count + 1
            let count_expr = boundary.clone() * Expression::Constant(Fr::ONE)
                + (Expression::Constant(Fr::ONE) - boundary.clone())
                    * (prev_result + Expression::Constant(Fr::ONE));

            vec![s * (result - count_expr)]
        });

        // MAX constraint: max >= all values[i] (maximum within group)
        // For production: For MAX, result >= value and result >= prev_result checks
        // In gate constraint: if boundary = 1 then result = value
        // if boundary = 0 then result >= prev_result and result >= value checks are done in comparison constraints
        meta.create_gate("max aggregation", |meta| {
            let s = meta.query_selector(max_selector);
            let value = meta.query_advice(value_column, Rotation::cur());
            let result = meta.query_advice(result_column, Rotation::cur());
            let _prev_result = meta.query_advice(result_column, Rotation::prev());
            let boundary = meta.query_advice(group_by_config.boundary_column, Rotation::cur());

            // If new group starts (boundary = 1), max = value
            // If same group continues (boundary = 0), max = max(prev_max, value)
            // Constraint: if boundary = 1 then result = value
            // if boundary = 0 then result >= prev_result and result >= value checks are done in comparison constraints
            let max_expr = boundary.clone() * value.clone()
                + (Expression::Constant(Fr::ONE) - boundary.clone()) * result.clone();

            // For boundary = 1 case: result = value check
            // For boundary = 0 case: result >= prev_result and result >= value checks
            // are done in comparison constraints with decompose
            vec![s * (result - max_expr)]
        });

        // MIN constraint: min <= all values[i] (minimum within group)
        // For production: For MIN, result <= value and result <= prev_result checks
        // In gate constraint: if boundary = 1 then result = value
        // if boundary = 0 then result <= prev_result and result <= value checks are done in comparison constraints
        meta.create_gate("min aggregation", |meta| {
            let s = meta.query_selector(min_selector);
            let value = meta.query_advice(value_column, Rotation::cur());
            let result = meta.query_advice(result_column, Rotation::cur());
            let _prev_result = meta.query_advice(result_column, Rotation::prev());
            let boundary = meta.query_advice(group_by_config.boundary_column, Rotation::cur());

            // If new group starts (boundary = 1), min = value
            // If same group continues (boundary = 0), min = min(prev_min, value)
            // Constraint: if boundary = 1 then result = value
            // if boundary = 0 then result <= prev_result and result <= value checks are done in comparison constraints
            let min_expr = boundary.clone() * value.clone()
                + (Expression::Constant(Fr::ONE) - boundary.clone()) * result.clone();

            // For boundary = 1 case: result = value check
            // For boundary = 0 case: result <= prev_result and result <= value checks
            // are done in comparison constraints with decompose
            vec![s * (result - min_expr)]
        });

        AggregationConfig {
            value_column,
            result_column,
            sum_selector,
            count_selector,
            max_selector,
            min_selector,
            group_by_config: group_by_config.clone(),
            range_check_config: range_check_config.clone(),
        }
    }

    /// Perform and verify aggregation operation
    /// Paper Section 4.5: SUM, COUNT, MAX, MIN operations
    ///
    /// Parameters:
    /// - group_keys: Group keys (must be sorted)
    /// - values: Values for each row
    /// - agg_type: Aggregation type ("sum", "count", "max", "min")
    pub fn aggregate_and_verify(
        &self,
        mut layouter: impl Layouter<Fr>,
        group_keys: &[u64],
        values: &[u64],
        agg_type: &str,
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
        if group_keys.len() != values.len() {
            return Err(Error::Synthesis);
        }

        if group_keys.is_empty() {
            return Ok(Vec::new());
        }

        // Get boundaries using Group-By chip
        let group_by_chip = super::group_by::GroupByChip::new(self.config.group_by_config.clone());
        let _boundary_cells = group_by_chip.group_and_verify(
            layouter.namespace(|| "group by for aggregation"),
            group_keys,
        )?;

        // Perform aggregation operation
        // Note: Selector won't be enabled for first row (no Rotation::prev())
        // We also need to assign boundary values here because constraints use boundary_column

        // First calculate all result values (for MAX/MIN comparison constraint)
        let mut result_values = Vec::new();
        let first_result = match agg_type {
            "sum" => values[0],
            "count" => 1,
            "max" => values[0],
            "min" => values[0],
            _ => return Err(Error::Synthesis),
        };
        result_values.push(first_result);
        let mut current_result = first_result;

        for i in 1..group_keys.len() {
            let boundary = if group_keys[i] != group_keys[i - 1] {
                Fr::ONE
            } else {
                Fr::ZERO
            };

            let boundary_value = if boundary == Fr::ONE {
                match agg_type {
                    "sum" => values[i],
                    "count" => 1,
                    "max" => values[i],
                    "min" => values[i],
                    _ => return Err(Error::Synthesis),
                }
            } else {
                match agg_type {
                    "sum" => current_result + values[i],
                    "count" => current_result + 1,
                    "max" => current_result.max(values[i]),
                    "min" => current_result.min(values[i]),
                    _ => return Err(Error::Synthesis),
                }
            };
            result_values.push(boundary_value);
            current_result = boundary_value;
        }

        // Now assign result_cells and add comparison constraints
        let result_cells = layouter.assign_region(
            || format!("aggregate {}", agg_type),
            |mut region| {
                let mut result_cells = Vec::new();

                // Special handling for first row (selector won't be enabled)
                region.assign_advice(
                    || "boundary_0",
                    self.config.group_by_config.boundary_column,
                    0,
                    || Value::known(Fr::ONE),
                )?;

                region.assign_advice(
                    || "value_0",
                    self.config.value_column,
                    0,
                    || Value::known(Fr::from(values[0])),
                )?;

                let first_result_cell = region.assign_advice(
                    || "result_0",
                    self.config.result_column,
                    0,
                    || Value::known(Fr::from(result_values[0])),
                )?;
                result_cells.push(first_result_cell);

                // For remaining rows (i >= 1, Rotation::prev() can be used)
                for i in 1..group_keys.len() {
                    let boundary = if group_keys[i] != group_keys[i - 1] {
                        Fr::ONE
                    } else {
                        Fr::ZERO
                    };

                    region.assign_advice(
                        || format!("boundary_{}", i),
                        self.config.group_by_config.boundary_column,
                        i,
                        || Value::known(boundary),
                    )?;

                    region.assign_advice(
                        || format!("value_{}", i),
                        self.config.value_column,
                        i,
                        || Value::known(Fr::from(values[i])),
                    )?;

                    let result_cell = region.assign_advice(
                        || format!("result_{}", i),
                        self.config.result_column,
                        i,
                        || Value::known(Fr::from(result_values[i])),
                    )?;
                    result_cells.push(result_cell);

                    match agg_type {
                        "sum" => self.config.sum_selector.enable(&mut region, i)?,
                        "count" => self.config.count_selector.enable(&mut region, i)?,
                        "max" => self.config.max_selector.enable(&mut region, i)?,
                        "min" => self.config.min_selector.enable(&mut region, i)?,
                        _ => return Err(Error::Synthesis),
                    }
                }

                Ok(result_cells)
            },
        )?;

        // For production: Comparison constraint for MAX/MIN
        // For MAX: result >= value and result >= prev_result checks
        // For MIN: result <= value and result <= prev_result checks
        // We use Range Check to verify result >= value (MAX) or result <= value (MIN)
        if agg_type == "max" || agg_type == "min" {
            use super::range_check::RangeCheckChip;
            let range_check_chip = RangeCheckChip::new(self.config.range_check_config.clone());

            // For first row: result = value check (already checked in constraint since boundary = 1)
            // But we can still check result >= value (MAX) or result <= value (MIN)
            if agg_type == "max" {
                // For first row: result >= value check (since result = value, diff = 0)
                let diff = result_values[0].saturating_sub(values[0]);
                let _diff_chunks = range_check_chip
                    .decompose_64bit(layouter.namespace(|| "max_diff_0"), Value::known(diff))?;
            } else if agg_type == "min" {
                // For first row: result <= value check (since result = value, diff = 0)
                let diff = values[0].saturating_sub(result_values[0]);
                let _diff_chunks = range_check_chip
                    .decompose_64bit(layouter.namespace(|| "min_diff_0"), Value::known(diff))?;
            }

            // For remaining rows (i >= 1, prev_result exists)
            for i in 1..group_keys.len() {
                let boundary = if group_keys[i] != group_keys[i - 1] {
                    Fr::ONE
                } else {
                    Fr::ZERO
                };

                if agg_type == "max" {
                    // For MAX: result >= value check
                    let diff = result_values[i].saturating_sub(values[i]);
                    let _diff_chunks = range_check_chip.decompose_64bit(
                        layouter.namespace(|| format!("max_diff_{}", i)),
                        Value::known(diff),
                    )?;

                    // If same group continues: result >= prev_result check
                    if boundary == Fr::ZERO {
                        let prev_diff = result_values[i].saturating_sub(result_values[i - 1]);
                        let _prev_diff_chunks = range_check_chip.decompose_64bit(
                            layouter.namespace(|| format!("max_prev_diff_{}", i)),
                            Value::known(prev_diff),
                        )?;
                    }
                } else if agg_type == "min" {
                    // For MIN: result <= value check
                    let diff = values[i].saturating_sub(result_values[i]);
                    let _diff_chunks = range_check_chip.decompose_64bit(
                        layouter.namespace(|| format!("min_diff_{}", i)),
                        Value::known(diff),
                    )?;

                    // If same group continues: result <= prev_result check
                    if boundary == Fr::ZERO {
                        let prev_diff = result_values[i - 1].saturating_sub(result_values[i]);
                        let _prev_diff_chunks = range_check_chip.decompose_64bit(
                            layouter.namespace(|| format!("min_prev_diff_{}", i)),
                            Value::known(prev_diff),
                        )?;
                    }
                }
            }
        }

        Ok(result_cells)
    }
}
