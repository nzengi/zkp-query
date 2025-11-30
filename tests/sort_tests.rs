use halo2_proofs::{
    circuit::Value,
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas::Base as Fr;
use poneglyphdb::circuit::*;

/// Sort Gate test circuit
/// According to Paper Section 4.2: Sorting verification with Grand Product Argument
#[derive(Clone)]
struct SortTestCircuit {
    input: Vec<u64>,
}

/// Config for test circuit
#[derive(Clone)]
struct TestConfig {
    poneglyph_config: PoneglyphConfig,
    range_check_config: RangeCheckConfig,
    sort_config: SortConfig,
}

impl Circuit<Fr> for SortTestCircuit {
    type Config = TestConfig;
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            input: vec![],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let poneglyph_config = PoneglyphConfig::configure(meta);
        let range_check_config = RangeCheckChip::configure(meta, &poneglyph_config);
        let sort_config = SortChip::configure(meta, &poneglyph_config, &range_check_config);
        
        TestConfig {
            poneglyph_config,
            range_check_config,
            sort_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), Error> {
        // Load lookup table
        config.poneglyph_config.load_lookup_table(&mut layouter)?;
        
        // Create sort chip
        let sort_chip = SortChip::new(config.sort_config);
        
        // Prepare input as Value::known()
        let input_values: Vec<Value<u64>> = self.input.iter().map(|&v| Value::known(v)).collect();
        
        // Sort input (as witness)
        let mut sorted_values = self.input.clone();
        sorted_values.sort();
        
        // Sort and verify
        let _output = sort_chip.sort_and_verify(
            layouter.namespace(|| "sort and verify"),
            input_values,
            sorted_values,
        )?;
        
        Ok(())
    }
}

#[test]
fn test_sort_simple() {
    // Test: Simple sorting
    let k = 10;
    let circuit = SortTestCircuit {
        input: vec![3, 1, 4, 1, 5],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_sort_already_sorted() {
    // Test: Already sorted array
    let k = 10;
    let circuit = SortTestCircuit {
        input: vec![1, 2, 3, 4, 5],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_sort_reverse() {
    // Test: Reverse sorted array
    let k = 10;
    let circuit = SortTestCircuit {
        input: vec![5, 4, 3, 2, 1],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_sort_single() {
    // Test: Single element array
    let k = 10;
    let circuit = SortTestCircuit {
        input: vec![42],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_sort_duplicates() {
    // Test: Duplicate values
    let k = 10;
    let circuit = SortTestCircuit {
        input: vec![3, 1, 3, 1, 2],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_sort_large() {
    // Test: Large array
    let k = 12; // Larger k value required
    let circuit = SortTestCircuit {
        input: (0..50).rev().collect(),
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

