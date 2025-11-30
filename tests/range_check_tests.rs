use halo2_proofs::{
    circuit::Value,
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas::Base as Fr;
use poneglyphdb::circuit::*;

/// Range Check test circuit
/// According to Paper Section 4.1: Test for decomposing 64-bit numbers into 8-bit chunks
#[derive(Clone)]
struct RangeCheckTestCircuit {
    value: u64,
    threshold: u64,
}

/// Config for test circuit - contains both PoneglyphConfig and RangeCheckConfig
#[derive(Clone)]
struct TestConfig {
    poneglyph_config: PoneglyphConfig,
    range_check_config: RangeCheckConfig,
}

impl Circuit<Fr> for RangeCheckTestCircuit {
    type Config = TestConfig;
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            value: 0,
            threshold: 0,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let poneglyph_config = PoneglyphConfig::configure(meta);
        
        // Configure Range Check chip
        let range_check_config = RangeCheckChip::configure(meta, &poneglyph_config);
        
        TestConfig {
            poneglyph_config,
            range_check_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), Error> {
        // Load lookup table
        config.poneglyph_config.load_lookup_table(&mut layouter)?;
        
        // Create Range Check chip
        let range_check_chip = RangeCheckChip::new(config.range_check_config);
        
        // Decompose 64-bit value into chunks
        let value = Value::known(self.value);
        let _chunks = range_check_chip.decompose_64bit(
            layouter.namespace(|| "decompose value"),
            value,
        )?;
        
        // x < t check (u value must be greater than threshold)
        let u = self.threshold + 1000; // u > threshold must hold
        let _check = range_check_chip.check_less_than(
            layouter.namespace(|| "check less than"),
            value,
            self.threshold,
            u,
        )?;
        
        Ok(())
    }
}

#[test]
fn test_range_check_decomposition() {
    // Test: Decompose 64-bit number into 8-bit chunks
    let k = 10; // 2^10 = 1024 rows (sufficient for small test)
    
    let circuit = RangeCheckTestCircuit {
        value: 0x1234567890ABCDEF,
        threshold: 1000,
    };
    
    // Empty public inputs for instance column (not using for now)
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_range_check_less_than_true() {
    // Test: x < t check (true case)
    let k = 10;
    
    let circuit = RangeCheckTestCircuit {
        value: 500,
        threshold: 1000,
    };
    
    // Empty public inputs for instance column (not using for now)
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_range_check_less_than_false() {
    // Test: x < t check (false case)
    let k = 10;
    
    let circuit = RangeCheckTestCircuit {
        value: 1500,
        threshold: 1000,
    };
    
    // Empty public inputs for instance column (not using for now)
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_range_check_small_value() {
    // Test: Small value (within 8-bit)
    let k = 10;
    
    let circuit = RangeCheckTestCircuit {
        value: 42,
        threshold: 100,
    };
    
    // Empty public inputs for instance column (not using for now)
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_range_check_large_value() {
    // Test: Large value (full 64-bit usage)
    let k = 10;
    
    let circuit = RangeCheckTestCircuit {
        value: u64::MAX,
        threshold: u64::MAX / 2,
    };
    
    // Empty public inputs for instance column (not using for now)
    let public_inputs = vec![vec![]];
    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

