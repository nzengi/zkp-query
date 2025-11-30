use halo2_proofs::{
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas::Base as Fr;
use poneglyphdb::circuit::*;

/// Group-By Gate test circuit
/// According to Paper Section 4.3: Group verification with Boundary Check
#[derive(Clone)]
struct GroupByTestCircuit {
    group_keys: Vec<u64>,
}

/// Config for test circuit
#[derive(Clone)]
struct TestConfig {
    poneglyph_config: PoneglyphConfig,
    range_check_config: RangeCheckConfig,
    group_by_config: GroupByConfig,
}

impl Circuit<Fr> for GroupByTestCircuit {
    type Config = TestConfig;
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            group_keys: vec![],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let poneglyph_config = PoneglyphConfig::configure(meta);
        let range_check_config = RangeCheckChip::configure(meta, &poneglyph_config);
        let group_by_config = GroupByChip::configure(meta, &poneglyph_config, &range_check_config);
        
        TestConfig {
            poneglyph_config,
            range_check_config,
            group_by_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), Error> {
        // Load lookup table
        config.poneglyph_config.load_lookup_table(&mut layouter)?;
        
        // Create Group-By chip
        let group_by_chip = GroupByChip::new(config.group_by_config);
        
        // Group keys must be sorted (comes after Sort Gate)
        // For test, we use already sorted group keys
        let mut sorted_keys = self.group_keys.clone();
        sorted_keys.sort();
        
        // Group and verify
        let _boundaries = group_by_chip.group_and_verify(
            layouter.namespace(|| "group and verify"),
            &sorted_keys,
        )?;
        
        Ok(())
    }
}

#[test]
fn test_group_by_single_group() {
    // Test: Single group (all keys same)
    let k = 10;
    let circuit = GroupByTestCircuit {
        group_keys: vec![1, 1, 1, 1, 1],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_group_by_multiple_groups() {
    // Test: Multiple groups
    let k = 10;
    let circuit = GroupByTestCircuit {
        group_keys: vec![1, 1, 2, 2, 2, 3, 3],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_group_by_single_element_groups() {
    // Test: Each element is a separate group
    let k = 10;
    let circuit = GroupByTestCircuit {
        group_keys: vec![1, 2, 3, 4, 5],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_group_by_empty() {
    // Test: Empty group (edge case)
    let k = 10;
    let circuit = GroupByTestCircuit {
        group_keys: vec![],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_group_by_single_element() {
    // Test: Single element
    let k = 10;
    let circuit = GroupByTestCircuit {
        group_keys: vec![42],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_group_by_large_dataset() {
    // Test: Large dataset (many groups)
    let k = 12;
    let mut group_keys = Vec::new();
    // 5 groups, each with 10 elements
    for group_id in 0..5 {
        for _ in 0..10 {
            group_keys.push(group_id);
        }
    }
    let circuit = GroupByTestCircuit {
        group_keys,
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_group_by_mixed_sizes() {
    // Test: Groups of different sizes
    let k = 10;
    let circuit = GroupByTestCircuit {
        group_keys: vec![1, 1, 2, 3, 3, 3, 3, 4, 5, 5],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

