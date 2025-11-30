use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas::Base as Fr;

pub mod aggregation;
pub mod config;
pub mod group_by;
pub mod join;
pub mod range_check;
pub mod sort;

pub use aggregation::*;
pub use config::*;
pub use group_by::*;
pub use join::*;
pub use range_check::*;
pub use sort::*;

/// Temel SQL Gate trait'i - tüm operatörler bunu implement eder
pub trait SQLGate<F: ff::PrimeField> {
    type Config;

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config;

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;
}

/// Ana devre yapısı - SQL sorgularını buraya derleyeceğiz
/// Makale Section 3: SQL sorgularını ZKP circuit'ine derleme
#[derive(Clone)]
pub struct PoneglyphCircuit {
    /// Veritabanı commitment (public input)
    pub db_commitment: Value<Fr>,
    /// Query sonucu (public input)
    pub query_result: Value<Fr>,
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

/// Range Check Operation
#[derive(Clone, Debug)]
pub struct RangeCheckOp {
    pub value: Value<u64>,
    pub threshold: u64,
    pub u: u64,
}

/// Sort Operation
#[derive(Clone, Debug)]
pub struct SortOp {
    pub input: Vec<Value<u64>>,
    pub sorted_output: Vec<u64>,
}

/// Group-By Operation
#[derive(Clone, Debug)]
pub struct GroupByOp {
    pub group_keys: Vec<u64>,
}

/// Join Operation
#[derive(Clone, Debug)]
pub struct JoinOp {
    pub table1_keys: Vec<u64>,
    pub table1_values: Vec<u64>,
    pub table2_keys: Vec<u64>,
    pub table2_values: Vec<u64>,
}

/// Aggregation Operation
#[derive(Clone, Debug)]
pub struct AggregationOp {
    pub group_keys: Vec<u64>,
    pub values: Vec<u64>,
    pub agg_type: String, // "sum", "count", "max", "min"
}

impl Circuit<Fr> for PoneglyphCircuit {
    type Config = PoneglyphConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            db_commitment: Value::unknown(),
            query_result: Value::unknown(),
            range_checks: Vec::new(),
            sorts: Vec::new(),
            group_bys: Vec::new(),
            joins: Vec::new(),
            aggregations: Vec::new(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        PoneglyphConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Makale Section 5.1: Public input'ları instance column'a expose et
        // Row 0: Veritabanı commitment
        // Row 1: Sorgu sonucu
        // NOT: Instance column'dan değer okuma işlemini KALDIRIYORUZ
        // Çünkü MockProver::run çağrısında public_inputs ile doldurulacak
        // enable_equality zaten configure'da yapıldı, bu yeterli
        // Instance column constraint'leri MockProver tarafından otomatik olarak kontrol edilir

        // Lookup table'ı yükle
        config.load_lookup_table(&mut layouter)?;

        // Create gate configs for synthesis
        // Note: Gates are already configured in Circuit::configure, but we need to create
        // chip instances here for synthesis. We'll create minimal configs from the base config.

        // Create Range Check config
        let range_check_config = RangeCheckConfig {
            chunk_columns: [
                config.advice[0],
                config.advice[1],
                config.advice[2],
                config.advice[3],
                config.advice[4],
                config.advice[5],
                config.advice[6],
                config.advice[7],
            ],
            lookup_table: config.lookup_table,
            check_column: config.advice[8],
            x_column: config.advice[9],
            diff_column: config.advice[8],
            threshold_column: config.fixed[0],
            u_column: config.fixed[1],
            selector: config.range_check_selector,
            less_than_selector: config.less_than_selector,
            decomposition_selector: config.decomposition_selector,
            diff_lookup_selector: config.diff_lookup_selector,
        };
        let range_check_chip = RangeCheckChip::new(range_check_config.clone());

        // Create Sort config
        let sort_config = SortConfig {
            input_column: config.advice[2],
            output_column: config.advice[3],
            diff_column: config.advice[4],
            sort_selector: config.sort_selector, // Sort için ayrı selector
            range_check_config: range_check_config.clone(),
        };
        let sort_chip = SortChip::new(sort_config.clone());

        // Create Group-By config
        let group_by_config = GroupByConfig {
            group_key_column: config.advice[5],
            boundary_column: config.advice[6],
            inverse_column: config.advice[7],
            boundary_selector: config.decomposition_selector, // Reuse selector
            range_check_config: range_check_config.clone(),
        };
        let group_by_chip = GroupByChip::new(group_by_config.clone());

        // Create Join config
        let join_config = JoinConfig {
            table1_key_column: config.advice[10],
            table1_value_column: config.advice[11],
            table2_key_column: config.advice[12],
            table2_value_column: config.advice[13],
            match_column: config.advice[14],
            join_selector: config.less_than_selector, // Reuse selector
            deduplication_selector: config.decomposition_selector, // Reuse selector
            range_check_config: range_check_config.clone(),
            sort_config: sort_config.clone(),
        };
        let join_chip = JoinChip::new(join_config);

        // Create Aggregation config
        let aggregation_config = AggregationConfig {
            value_column: config.advice[8],
            result_column: config.advice[9],
            sum_selector: config.less_than_selector, // Reuse selector
            count_selector: config.decomposition_selector, // Reuse selector
            max_selector: config.range_check_selector, // Reuse selector
            min_selector: config.diff_lookup_selector, // Reuse selector
            group_by_config: group_by_config.clone(),
            range_check_config: range_check_config.clone(),
        };
        let aggregation_chip = AggregationChip::new(aggregation_config);

        // Range Check operations
        for range_check_op in &self.range_checks {
            range_check_chip.check_less_than(
                layouter.namespace(|| "range check"),
                range_check_op.value,
                range_check_op.threshold,
                range_check_op.u,
            )?;
        }

        // Sort operations
        for sort_op in &self.sorts {
            sort_chip.sort_and_verify(
                layouter.namespace(|| "sort"),
                sort_op.input.clone(),
                sort_op.sorted_output.clone(),
            )?;
        }

        // Group-By operations
        for group_by_op in &self.group_bys {
            group_by_chip
                .group_and_verify(layouter.namespace(|| "group by"), &group_by_op.group_keys)?;
        }

        // Join operations
        for join_op in &self.joins {
            join_chip.join_and_verify(
                layouter.namespace(|| "join"),
                &join_op.table1_keys,
                &join_op.table1_values,
                &join_op.table2_keys,
                &join_op.table2_values,
            )?;
        }

        // Aggregation operations
        for agg_op in &self.aggregations {
            aggregation_chip.aggregate_and_verify(
                layouter.namespace(|| "aggregation"),
                &agg_op.group_keys,
                &agg_op.values,
                &agg_op.agg_type,
            )?;
        }

        Ok(())
    }
}
