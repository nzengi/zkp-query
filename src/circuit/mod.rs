use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas::Base as Fr;

pub mod config;
pub mod range_check;
pub mod sort;
pub mod group_by;
pub mod join;
pub mod aggregation;

pub use config::*;
pub use range_check::*;
pub use sort::*;
pub use group_by::*;
pub use join::*;
pub use aggregation::*;

/// Basic SQL Gate trait - all operators implement this
pub trait SQLGate<F: ff::PrimeField> {
    type Config;
    
    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config;
    
    fn synthesize(
        &self,
        config: Self::Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;
}

/// Main circuit structure - SQL queries will be compiled here
#[derive(Clone)]
pub struct PoneglyphCircuit {
    // This structure will be filled with SQL query results in the future
}

impl Circuit<Fr> for PoneglyphCircuit {
    type Config = PoneglyphConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {}
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        PoneglyphConfig::configure(meta)
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Empty for now - will fill step by step
        Ok(())
    }
}

