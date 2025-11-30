use halo2_proofs::{
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas::Base as Fr;
use poneglyphdb::circuit::*;

/// Join Gate test circuit
/// According to Paper Section 4.4: Join verification with Match/Miss distinction
#[derive(Clone)]
struct JoinTestCircuit {
    table1_keys: Vec<u64>,
    table1_values: Vec<u64>,
    table2_keys: Vec<u64>,
    table2_values: Vec<u64>,
}

/// Config for test circuit
#[derive(Clone)]
struct TestConfig {
    poneglyph_config: PoneglyphConfig,
    range_check_config: RangeCheckConfig,
    sort_config: SortConfig,
    join_config: JoinConfig,
}

impl Circuit<Fr> for JoinTestCircuit {
    type Config = TestConfig;
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            table1_keys: vec![],
            table1_values: vec![],
            table2_keys: vec![],
            table2_values: vec![],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let poneglyph_config = PoneglyphConfig::configure(meta);
        let range_check_config = RangeCheckChip::configure(meta, &poneglyph_config);
        let sort_config = SortChip::configure(meta, &poneglyph_config, &range_check_config);
        let join_config = JoinChip::configure(meta, &poneglyph_config, &range_check_config, &sort_config);
        
        TestConfig {
            poneglyph_config,
            range_check_config,
            sort_config,
            join_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), Error> {
        // Load lookup table
        config.poneglyph_config.load_lookup_table(&mut layouter)?;
        
        // Create join chip
        let join_chip = JoinChip::new(config.join_config);
        
        // Join and verify
        let _matches = join_chip.join_and_verify(
            layouter.namespace(|| "join and verify"),
            &self.table1_keys,
            &self.table1_values,
            &self.table2_keys,
            &self.table2_values,
        )?;
        
        Ok(())
    }
}

#[test]
fn test_join_simple_inner() {
    // Test: Simple Inner Join
    let k = 10;
    let circuit = JoinTestCircuit {
        table1_keys: vec![1, 2, 3],
        table1_values: vec![10, 20, 30],
        table2_keys: vec![2, 3, 4],
        table2_values: vec![200, 300, 400],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_join_pk_fk() {
    // Test: PK-FK relationship
    let k = 10;
    let circuit = JoinTestCircuit {
        table1_keys: vec![1, 2, 3],      // Primary keys
        table1_values: vec![100, 200, 300],
        table2_keys: vec![1, 1, 2],      // Foreign keys (duplicates allowed)
        table2_values: vec![11, 12, 21],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_join_empty_table() {
    // Test: Empty table (edge case)
    let k = 10;
    let circuit = JoinTestCircuit {
        table1_keys: vec![],
        table1_values: vec![],
        table2_keys: vec![1, 2, 3],
        table2_values: vec![10, 20, 30],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_join_single_record() {
    // Test: Single record (edge case)
    let k = 10;
    let circuit = JoinTestCircuit {
        table1_keys: vec![42],
        table1_values: vec![100],
        table2_keys: vec![42],
        table2_values: vec![200],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_join_no_matches() {
    // Test: No matches
    let k = 10;
    let circuit = JoinTestCircuit {
        table1_keys: vec![1, 2, 3],
        table1_values: vec![10, 20, 30],
        table2_keys: vec![4, 5, 6],
        table2_values: vec![40, 50, 60],
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_join_large_dataset() {
    // Test: Large dataset
    let k = 12;
    let mut table1_keys = Vec::new();
    let mut table1_values = Vec::new();
    let mut table2_keys = Vec::new();
    let mut table2_values = Vec::new();
    
    // Create 10 records
    for i in 0..10 {
        table1_keys.push(i);
        table1_values.push(i * 10);
        table2_keys.push(i);
        table2_values.push(i * 100);
    }
    
    let circuit = JoinTestCircuit {
        table1_keys,
        table1_values,
        table2_keys,
        table2_values,
    };
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

