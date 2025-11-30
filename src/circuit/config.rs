use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance, Selector, TableColumn},
};
use pasta_curves::pallas::Base as Fr;

/// Main circuit configuration
/// According to Paper Section 5.1: BN254 curve, IPA commitment
/// 
/// # Column Allocation
/// 
/// ## Advice Columns (15 columns)
/// - `advice[0-7]`: Range Check chunk columns (for 8-bit decomposition)
/// - `advice[2-4]`: Sort Gate (input, output, diff) - shared with Range Check
/// - `advice[5-7]`: Group-By Gate (key, boundary, inverse) - shared with Range Check
/// - `advice[8-9]`: Range Check (check/x, diff) / Aggregation Gate (value, result)
/// - `advice[10-14]`: Join Gate (table1_key, table1_value, table2_key, table2_value, match_flag)
/// 
/// ## Fixed Columns (2 columns)
/// - `fixed[0]`: Threshold (t) value - used in Range Check
/// - `fixed[1]`: u value - used in Range Check
/// 
/// ## Instance Column (1 column)
/// - `instance`: For public data (database commitment, query result)
///   - Row 0: Database commitment
///   - Row 1: Query result
/// 
/// ## Table Column (1 column)
/// - `lookup_table`: Lookup table for values 0-255 (for 8-bit chunks)
#[derive(Clone, Debug)]
pub struct PoneglyphConfig {
    // Advice columns - for private data
    // Expanded from 10 to 15 for Join Gate support
    pub advice: [Column<Advice>; 15],
    
    // Fixed columns - for constant values
    // fixed[0]: Threshold (t) value
    // fixed[1]: u value
    pub fixed: [Column<Fixed>; 2],
    
    // Table column - for lookup table (values 0-255)
    pub lookup_table: TableColumn,
    
    // Instance columns - public data (commitment, query result)
    // Row 0: Database commitment
    // Row 1: Query result
    pub instance: Column<Instance>,
    
    // Selectors - to enable/disable gates
    // Common selectors for Range Check
    pub range_check_selector: Selector,
    pub less_than_selector: Selector,
    pub decomposition_selector: Selector,
    pub diff_lookup_selector: Selector,
    // Separate selector for Sort (to avoid conflicts with less_than_selector)
    pub sort_selector: Selector,
}

impl PoneglyphConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        // Create advice columns
        // Expanded from 10 to 15 for Join Gate support
        // 
        // Column Allocation:
        // - advice[0-7]: Range Check chunk columns (for 8-bit decomposition)
        // - advice[2-4]: Sort Gate (input, output, diff) - shared with Range Check
        // - advice[5-7]: Group-By Gate (key, boundary, inverse) - shared with Range Check
        // - advice[8-9]: Range Check (check/x, diff) / Aggregation Gate (value, result)
        // - advice[10-14]: Join Gate (table1_key, table1_value, table2_key, table2_value, match_flag)
        let advice = [
            meta.advice_column(), // 0 - Range Check chunk[0]
            meta.advice_column(), // 1 - Range Check chunk[1]
            meta.advice_column(), // 2 - Range Check chunk[2] / Sort input
            meta.advice_column(), // 3 - Range Check chunk[3] / Sort output
            meta.advice_column(), // 4 - Range Check chunk[4] / Sort diff
            meta.advice_column(), // 5 - Range Check chunk[5] / Group-By key
            meta.advice_column(), // 6 - Range Check chunk[6] / Group-By boundary
            meta.advice_column(), // 7 - Range Check chunk[7] / Group-By inverse
            meta.advice_column(), // 8 - Range Check check/x / Aggregation value
            meta.advice_column(), // 9 - Range Check diff / Aggregation result
            meta.advice_column(), // 10 - Join table1_key
            meta.advice_column(), // 11 - Join table1_value
            meta.advice_column(), // 12 - Join table2_key
            meta.advice_column(), // 13 - Join table2_value
            meta.advice_column(), // 14 - Join match_flag
        ];
        
        // Create fixed columns
        // fixed[0]: Threshold (t) value - used in Range Check
        // fixed[1]: u value - used in Range Check
        let fixed = [
            meta.fixed_column(), // 0 - Threshold (t) value
            meta.fixed_column(), // 1 - u value
        ];
        
        // Table column - for lookup table (values 0-255)
        let lookup_table = meta.lookup_table_column();
        
        // Instance column - for public data
        // Row 0: Database commitment
        // Row 1: Query result
        let instance = meta.instance_column();
        
        // Selectors
        // complex_selector required for lookup constraint
        let range_check_selector = meta.complex_selector();
        let less_than_selector = meta.selector();
        let decomposition_selector = meta.selector();
        let diff_lookup_selector = meta.complex_selector();
        let sort_selector = meta.selector();
        
        // Enable fixed columns (for threshold and u values)
        meta.enable_constant(fixed[0]);
        meta.enable_constant(fixed[1]);
        
        // Enable instance column
        meta.enable_equality(instance);
        
        // Enable advice columns (for equality)
        for col in &advice {
            meta.enable_equality(*col);
        }
        
        // Create temporary config for gate configuration
        let temp_config = Self {
            advice,
            fixed,
            lookup_table,
            instance,
            range_check_selector,
            less_than_selector,
            decomposition_selector,
            diff_lookup_selector,
            sort_selector,
        };
        
        // Configure all gates
        let _range_check_config =
            crate::circuit::range_check::RangeCheckChip::configure(meta, &temp_config);
        let _sort_config =
            crate::circuit::sort::SortChip::configure(meta, &temp_config, &_range_check_config);
        let _group_by_config = crate::circuit::group_by::GroupByChip::configure(
            meta,
            &temp_config,
            &_range_check_config,
        );
        let _join_config = crate::circuit::join::JoinChip::configure(
            meta,
            &temp_config,
            &_range_check_config,
            &_sort_config,
        );
        let _aggregation_config = crate::circuit::aggregation::AggregationChip::configure(
            meta,
            &temp_config,
            &_group_by_config,
            &_range_check_config,
        );
        
        temp_config
    }
    
    /// Fill lookup table (values 0-255)
    /// According to Paper Section 4.1: lookup table for 8-bit chunks
    /// According to Halo2 API: assign_table should be used
    /// 
    /// # Usage
    /// 
    /// ```rust,ignore
    /// config.load_lookup_table(&mut layouter)?;
    /// ```
    pub fn load_lookup_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "8-bit lookup table (0-255)",
            |mut table| {
                // Write values 0-255 to table column
                // Note: Halo2 example uses 1-256 but we use 0-255
                // because 8-bit chunks are in range 0-255
                for i in 0..256 {
                    table.assign_cell(
                        || format!("lookup value {}", i),
                        self.lookup_table,
                        i,
                        || Value::known(Fr::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
    
    /// Read public input from instance column and copy to advice column
    /// According to Paper Section 5.1: Public data (commitment, query result) in instance column
    /// 
    /// # Usage
    /// 
    /// ```rust,ignore
    /// // Read database commitment (row 0)
    /// let db_commitment = config.read_public_input(&mut layouter, 0)?;
    /// 
    /// // Read query result (row 1)
    /// let query_result = config.read_public_input(&mut layouter, 1)?;
    /// ```
    /// 
    /// # Note
    /// 
    /// Assigning values to instance column is done on the prover side (in MockProver::run() call).
    /// This function is used to read values from instance column and use them in constraints.
    pub fn read_public_input(
        &self,
        layouter: &mut impl Layouter<Fr>,
        row: usize,
    ) -> Result<Value<Fr>, Error> {
        layouter.assign_region(
            || format!("read public input row {}", row),
            |mut region| {
                // Read value from instance column
                let value = region.instance_value(self.instance, row)?;
                
                // Copy to advice column (to use in constraints)
                // Note: This is optional, just returning instance value is also sufficient
                // But copying to advice column may be needed to use in constraints
                region.assign_advice(
                    || format!("public_input_{}", row),
                    self.advice[0], // Temporarily using advice[0]
                    0,
                    || value,
                )?;
                
                Ok(value)
            },
        )
    }
    
    /// Assign public inputs to instance column (helper function)
    /// According to Paper Section 5.1: Database commitment and query result should be public inputs
    /// 
    /// # Usage
    /// 
    /// ```rust,ignore
    /// use halo2_proofs::dev::MockProver;
    /// 
    /// // Used in MockProver::run() call
    /// let public_inputs = vec![
    ///     vec![db_commitment], // Row 0: Database commitment
    ///     vec![query_result],  // Row 1: Query result
    /// ];
    /// let prover = MockProver::run(k, &circuit, public_inputs)?;
    /// ```
    /// 
    /// # Note
    /// 
    /// This function is for documentation purposes only. In actual usage,
    /// the public_inputs parameter is used in `MockProver::run()` or `create_proof()` calls.
    /// 
    /// # Public Input Layout
    /// 
    /// - Row 0: Database commitment (Fr)
    /// - Row 1: Query result (Fr)
    pub fn get_public_input_layout(
        db_commitment: Fr,
        query_result: Fr,
    ) -> Vec<Vec<Fr>> {
        vec![
            vec![db_commitment], // Row 0: Database commitment
            vec![query_result],  // Row 1: Query result
        ]
    }
}
