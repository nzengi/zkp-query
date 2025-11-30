use halo2_proofs::{
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas::Base as Fr;
use poneglyphdb::circuit::*;

/// Aggregation Gate test circuit
/// According to Paper Section 4.5: SUM, COUNT, MAX, MIN operations
#[derive(Clone)]
struct AggregationTestCircuit {
    group_keys: Vec<u64>,
    values: Vec<u64>,
    agg_type: String,
}

/// Config for test circuit
#[derive(Clone)]
struct TestConfig {
    poneglyph_config: PoneglyphConfig,
    range_check_config: RangeCheckConfig,
    group_by_config: GroupByConfig,
    aggregation_config: AggregationConfig,
}

impl Circuit<Fr> for AggregationTestCircuit {
    type Config = TestConfig;
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            group_keys: vec![],
            values: vec![],
            agg_type: String::new(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let poneglyph_config = PoneglyphConfig::configure(meta);
        let range_check_config = RangeCheckChip::configure(meta, &poneglyph_config);
        let group_by_config = GroupByChip::configure(meta, &poneglyph_config, &range_check_config);
        let aggregation_config = AggregationChip::configure(meta, &poneglyph_config, &group_by_config, &range_check_config);
        
        TestConfig {
            poneglyph_config,
            range_check_config,
            group_by_config,
            aggregation_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), Error> {
        // Load lookup table
        config.poneglyph_config.load_lookup_table(&mut layouter)?;
        
        // Group keys must be sorted (comes after Sort Gate)
        // For test, we use already sorted group keys
        let mut sorted_keys = self.group_keys.clone();
        sorted_keys.sort();
        
        // Create aggregation chip
        let aggregation_chip = AggregationChip::new(config.aggregation_config);
        
        // Aggregate and verify
        let _results = aggregation_chip.aggregate_and_verify(
            layouter.namespace(|| "aggregate and verify"),
            &sorted_keys,
            &self.values,
            &self.agg_type,
        )?;
        
        Ok(())
    }
}

#[test]
fn test_aggregation_sum_single_group() {
    // Test: SUM - Single group
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![1, 1, 1, 1, 1],
        values: vec![10, 20, 30, 40, 50],
        agg_type: "sum".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_aggregation_sum_multiple_groups() {
    // Test: SUM - Multiple groups
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![1, 1, 2, 2, 2, 3, 3],
        values: vec![10, 20, 30, 40, 50, 60, 70],
        agg_type: "sum".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_aggregation_count_single_group() {
    // Test: COUNT - Single group
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![1, 1, 1, 1, 1],
        values: vec![10, 20, 30, 40, 50],
        agg_type: "count".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_aggregation_count_multiple_groups() {
    // Test: COUNT - Multiple groups
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![1, 1, 2, 2, 2, 3, 3],
        values: vec![10, 20, 30, 40, 50, 60, 70],
        agg_type: "count".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_aggregation_max_single_group() {
    // Test: MAX - Single group
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![1, 1, 1, 1, 1],
        values: vec![10, 20, 30, 40, 50],
        agg_type: "max".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_aggregation_max_multiple_groups() {
    // Test: MAX - Multiple groups
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![1, 1, 2, 2, 2, 3, 3],
        values: vec![10, 20, 30, 40, 50, 60, 70],
        agg_type: "max".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_aggregation_min_single_group() {
    // Test: MIN - Single group
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![1, 1, 1, 1, 1],
        values: vec![10, 20, 30, 40, 50],
        agg_type: "min".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_aggregation_min_multiple_groups() {
    // Test: MIN - Multiple groups
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![1, 1, 2, 2, 2, 3, 3],
        values: vec![10, 20, 30, 40, 50, 60, 70],
        agg_type: "min".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_aggregation_empty() {
    // Test: Empty group (edge case)
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![],
        values: vec![],
        agg_type: "sum".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_aggregation_single_element() {
    // Test: Single element
    let k = 10;
    let circuit = AggregationTestCircuit {
        group_keys: vec![1],
        values: vec![42],
        agg_type: "sum".to_string(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

