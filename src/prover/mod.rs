// Prover and Verifier module
// Paper Section 5: Non-interactive ZKP proof generation and verification
//
// Halo2 0.3.1 real API usage:
// - Params<C> (IPA commitment scheme)
// - keygen_vk, keygen_pk
// - create_proof (requires transcript)
// - verify_proof (requires transcript and strategy)
//
// Note: Circuit uses Fr = pallas::Base = Fp, so we use EqAffine

use halo2_proofs::{
    dev::MockProver,
    pasta::EqAffine,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Error, ProvingKey, SingleVerifier,
        VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::pallas::Base as Fr;
use rand::rngs::OsRng;

use crate::circuit::PoneglyphCircuit;

/// Prover
/// Paper Section 5: Non-interactive ZKP proof generation
///
/// Implementation using Halo2 0.3.1 real API
pub struct Prover {
    /// Proving key
    pk: ProvingKey<EqAffine>,
}

impl Prover {
    /// Create new prover
    /// Paper Section 5: Proving key generation
    ///
    /// Halo2 0.3.1 real API: keygen_pk(params, vk, circuit)
    pub fn new(params: &Params<EqAffine>, circuit: &PoneglyphCircuit) -> Result<Self, Error> {
        // Create verifying key
        let vk = keygen_vk(params, circuit)?;

        // Create proving key
        let pk = keygen_pk(params, vk, circuit)?;

        Ok(Self { pk })
    }

    /// Create proof
    /// Paper Section 5: Non-interactive proof generation
    ///
    /// Halo2 0.3.1 real API: create_proof(params, pk, circuits, instances, rng, transcript)
    pub fn prove(
        &self,
        params: &Params<EqAffine>,
        circuit: &PoneglyphCircuit,
        public_inputs: &[Vec<Fr>],
    ) -> Result<Vec<u8>, Error> {
        // Create transcript (Blake2bWrite)
        let mut transcript =
            Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(vec![]);

        // Format instances: &[&[&[C::Scalar]]]
        // public_inputs: &[Vec<Fr>] -> instances: &[&[&[Fr]]]
        // Each public_input represents an instance column
        let instances: Vec<Vec<&[Fr]>> =
            public_inputs.iter().map(|pi| vec![pi.as_slice()]).collect();
        let instances_refs: Vec<&[&[Fr]]> = instances.iter().map(|inst| inst.as_slice()).collect();

        // Create proof
        // Note: create_proof expects &[ConcreteCircuit], so we use &[circuit.clone()]
        // Circuit implements Clone
        create_proof(
            params,
            &self.pk,
            &[circuit.clone()],
            &instances_refs,
            OsRng,
            &mut transcript,
        )?;

        // Get proof (transcript.finalize())
        Ok(transcript.finalize())
    }
}

/// Verifier
/// Paper Section 5: Non-interactive ZKP proof verification
///
/// Implementation using Halo2 0.3.1 real API
pub struct Verifier {
    /// Verifying key
    vk: VerifyingKey<EqAffine>,
}

impl Verifier {
    /// Create new verifier
    /// Paper Section 5: Verifying key generation
    ///
    /// Halo2 0.3.1 real API: keygen_vk(params, circuit)
    pub fn new(params: &Params<EqAffine>, circuit: &PoneglyphCircuit) -> Result<Self, Error> {
        // Create verifying key
        let vk = keygen_vk(params, circuit)?;

        Ok(Self { vk })
    }

    /// Verify proof
    /// Paper Section 5: Non-interactive proof verification
    ///
    /// Halo2 0.3.1 real API: verify_proof(params, vk, strategy, instances, transcript)
    pub fn verify(
        &self,
        params: &Params<EqAffine>,
        proof: &[u8],
        public_inputs: &[Vec<Fr>],
    ) -> Result<bool, Error> {
        // Create transcript (Blake2bRead)
        let mut transcript = Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(proof);

        // Create verification strategy (SingleVerifier)
        let strategy = SingleVerifier::new(params);

        // Format instances: &[&[&[C::Scalar]]]
        // public_inputs: &[Vec<Fr>] -> instances: &[&[&[Fr]]]
        let instances: Vec<Vec<&[Fr]>> =
            public_inputs.iter().map(|pi| vec![pi.as_slice()]).collect();
        let instances_refs: Vec<&[&[Fr]]> = instances.iter().map(|inst| inst.as_slice()).collect();

        // Verify proof
        verify_proof(params, &self.vk, strategy, &instances_refs, &mut transcript)?;

        Ok(true)
    }
}

/// Mock Prover Helper (for testing)
/// Paper Section 5: Mock prover for development and testing
pub struct MockProverHelper;

impl MockProverHelper {
    /// Create and verify mock proof (for testing)
    /// Paper Section 5: For development and testing
    pub fn mock_prove_and_verify(
        circuit: &PoneglyphCircuit,
        public_inputs: &[Vec<Fr>],
        k: u32,
    ) -> Result<bool, String> {
        // In Halo2, MockProver::run format: Vec<Vec<Fr>> (each inner vector is an instance column)
        // public_inputs is already in Vec<Vec<Fr>> format, so we can use it directly
        let prover = MockProver::run(k, circuit, public_inputs.to_vec())
            .map_err(|e| format!("Failed to run mock prover: {:?}", e))?;

        prover
            .verify()
            .map_err(|e| format!("Failed to verify mock proof: {:?}", e))?;

        Ok(true)
    }
}
