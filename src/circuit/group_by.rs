use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas::Base as Fr;

use super::config::PoneglyphConfig;
use super::range_check::RangeCheckConfig;

/// Group-By Gate Configuration
/// According to Paper Section 4.3: Group verification with Boundary Check
///
/// # Column Allocation
///
/// - `group_key_column`: For group key values (advice[5])
/// - `boundary_column`: For boundary flags (advice[6]) - b = 1 means new group start
/// - `inverse_column`: For inverse value (advice[7]) - p = 1/(v₁ - v₂) if v₁ ≠ v₂, else p = 0
///
/// # Note
///
/// Group-By Gate uses Sort Gate's output. Group keys must be sorted.
/// According to Paper Section 4.3, sorting is done first with Sort Gate, then
/// boundary check is done with Group-By Gate.
#[derive(Clone, Debug)]
pub struct GroupByConfig {
    // Advice column for group key values
    // advice[5] - shared with Range Check chunk[5]
    pub group_key_column: Column<Advice>,

    // Advice column for boundary flags (b = 1 means new group start)
    // advice[6] - shared with Range Check chunk[6]
    pub boundary_column: Column<Advice>,

    // Advice column for inverse value (p = 1/(v₁ - v₂) if v₁ ≠ v₂, else p = 0)
    // advice[7] - shared with Range Check chunk[7]
    pub inverse_column: Column<Advice>,

    // Selector for boundary check
    pub boundary_selector: Selector,

    // Range Check integration (for additional validation - currently unused)
    pub range_check_config: RangeCheckConfig,
}

/// Group-By Chip
/// Paper Section 4.3 implementation
pub struct GroupByChip {
    config: GroupByConfig,
}

impl GroupByChip {
    /// Create new GroupByChip
    pub fn new(config: GroupByConfig) -> Self {
        Self { config }
    }

    /// Configure the Group-By Gate
    /// Paper Section 4.3: Boundary Check constraint
    /// Formula: b = 1 - (v₁ - v₂) × p
    /// where p = 1/(v₁ - v₂) if v₁ ≠ v₂, else p = 0
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        config: &PoneglyphConfig,
        range_check_config: &RangeCheckConfig,
    ) -> GroupByConfig {
        // Get advice columns
        // Column allocation (see PoneglyphConfig documentation):
        // - advice[0-7]: Range Check chunk columns (for 8-bit decomposition)
        // - advice[2-4]: Sort Gate (input, output, diff) - shared with Range Check
        // - advice[5-7]: Group-By Gate (key, boundary, inverse) - shared with Range Check
        //
        // Note: Group-By Gate uses Sort Gate's output. Group keys must be sorted.
        let group_key_column = config.advice[5];
        let boundary_column = config.advice[6];
        let inverse_column = config.advice[7];

        // Create selector
        let boundary_selector = meta.selector();

        // Add boundary check constraint
        // Paper Section 4.3: b = 1 - (v₁ - v₂) × p
        //
        // This constraint verifies group boundaries
        // v₁ = group_key[i], v₂ = group_key[i+1]
        // b = 1 means new group has started
        //
        // Inverse calculation: p = 1/(v₁ - v₂) if v₁ ≠ v₂, else p = 0
        // p value will be calculated in witness and assigned to inverse_column
        meta.create_gate("boundary check", |meta| {
            let s = meta.query_selector(boundary_selector);
            let v1 = meta.query_advice(group_key_column, Rotation::cur());
            let v2 = meta.query_advice(group_key_column, Rotation::next());
            let b = meta.query_advice(boundary_column, Rotation::cur());
            let p = meta.query_advice(inverse_column, Rotation::cur());

            // Paper formula: b = 1 - (v₁ - v₂) × p
            let diff = v2.clone() - v1.clone();
            let boundary_expr = Expression::Constant(Fr::ONE) - (diff.clone() * p.clone());

            // Boolean constraint: b × (1 - b) = 0
            let bool_check = b.clone() * (Expression::Constant(Fr::ONE) - b.clone());

            // Inverse constraint: p × (v₁ - v₂) = 1 - b
            // If v₁ = v₂: p = 0, b = 1, so 0 × 0 = 1 - 1 = 0 ✓
            // If v₁ ≠ v₂: p = 1/(v₁ - v₂), b = 0, so (1/(v₁ - v₂)) × (v₁ - v₂) = 1 - 0 = 1 ✓
            let inverse_check =
                p.clone() * diff.clone() - (Expression::Constant(Fr::ONE) - b.clone());

            vec![
                s.clone() * bool_check,          // b must be boolean
                s.clone() * (b - boundary_expr), // b = 1 - (v₁ - v₂) × p
                s.clone() * inverse_check,       // p × (v₁ - v₂) = 1 - b
            ]
        });

        GroupByConfig {
            group_key_column,
            boundary_column,
            inverse_column,
            boundary_selector,
            range_check_config: range_check_config.clone(),
        }
    }

    /// Assign group keys and verify boundaries
    /// Paper Section 4.3: Group verification with Boundary Check
    ///
    /// # Requirements
    ///
    /// - `group_keys` must be sorted (Sort Gate output)
    /// - Group keys must be assigned in consecutive rows
    ///
    /// # Boundary Check Logic
    ///
    /// - `b = 1`: New group has started (v₁ = v₂)
    /// - `b = 0`: Same group continues (v₁ ≠ v₂)
    ///
    /// # Return Value
    ///
    /// List of boundary cells (one boundary for each consecutive pair)
    pub fn group_and_verify(
        &self,
        mut layouter: impl Layouter<Fr>,
        group_keys: &[u64],
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
        // Assign group keys and boundaries in the same region
        // Since constraints use Rotation::cur() and Rotation::next(),
        // they must be in consecutive rows
        layouter.assign_region(
            || "group and verify",
            |mut region| {
                let mut boundary_cells = Vec::new();

                // For empty group
                if group_keys.is_empty() {
                    return Ok(boundary_cells);
                }

                // For single element
                if group_keys.len() == 1 {
                    // Assign group key
                    region.assign_advice(
                        || "group_key_0",
                        self.config.group_key_column,
                        0,
                        || Value::known(Fr::from(group_keys[0])),
                    )?;

                    let boundary_cell = region.assign_advice(
                        || "boundary_0",
                        self.config.boundary_column,
                        0,
                        || Value::known(Fr::ZERO),
                    )?;
                    let _inverse_cell = region.assign_advice(
                        || "inverse_0",
                        self.config.inverse_column,
                        0,
                        || Value::known(Fr::ZERO),
                    )?;
                    boundary_cells.push(boundary_cell);
                    return Ok(boundary_cells);
                }

                // Assign group keys
                for (i, key) in group_keys.iter().enumerate() {
                    region.assign_advice(
                        || format!("group_key_{}", i),
                        self.config.group_key_column,
                        i,
                        || Value::known(Fr::from(*key)),
                    )?;
                }

                // Calculate and assign boundary for each consecutive pair
                for i in 0..(group_keys.len() - 1) {
                    // v₁ = group_keys[i], v₂ = group_keys[i+1]
                    let v1 = group_keys[i];
                    let v2 = group_keys[i + 1];

                    // Paper formula: b = 1 - (v₁ - v₂) × p
                    // p = 1/(v₁ - v₂) if v₁ ≠ v₂, else p = 0
                    let diff = v2 as i64 - v1 as i64;

                    let (boundary, inverse) = if diff == 0 {
                        // v₁ = v₂: p = 0, b = 1 (new group has started)
                        // Paper formula: b = 1 - (v₁ - v₂) × p = 1 - 0 × 0 = 1
                        (Fr::ONE, Fr::ZERO)
                    } else {
                        // v₁ ≠ v₂: p = 1/(v₁ - v₂), b = 0 (same group continues)
                        // Calculate diff as field element
                        let diff_field = if diff > 0 {
                            Fr::from(diff as u64)
                        } else {
                            // Negative diff: negative value in field
                            // Note: Since group keys are sorted, diff should generally be >= 0
                            // But we handle negative values for field arithmetic
                            let abs_diff = (-diff) as u64;
                            -Fr::from(abs_diff)
                        };

                        // Calculate inverse: p = 1/(v₁ - v₂)
                        // Note: Since diff_field ≠ 0, invert() should succeed
                        // But we use unwrap_or(Fr::ZERO) for safety
                        // If invert() fails (very rare), p = 0
                        // In this case, constraints will error
                        let inv = diff_field.invert().unwrap_or(Fr::ZERO);
                        (Fr::ZERO, inv)
                    };

                    let boundary_cell = region.assign_advice(
                        || format!("boundary_{}", i),
                        self.config.boundary_column,
                        i,
                        || Value::known(boundary),
                    )?;

                    let _inverse_cell = region.assign_advice(
                        || format!("inverse_{}", i),
                        self.config.inverse_column,
                        i,
                        || Value::known(inverse),
                    )?;

                    // Enable boundary selector
                    self.config.boundary_selector.enable(&mut region, i)?;

                    boundary_cells.push(boundary_cell);
                }

                Ok(boundary_cells)
            },
        )
    }
}
