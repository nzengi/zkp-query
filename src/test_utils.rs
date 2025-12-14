/// Test utilities for circuit testing

#[cfg(test)]
pub mod test_helpers {
    use crate::circuit::*;
    use halo2_proofs::circuit::Value;
    use pasta_curves::pallas::Base as Fr;

    /// Generate a sorted array of values
    pub fn generate_sorted_values(n: usize, start: u64) -> Vec<u64> {
        (0..n).map(|i| start + i as u64).collect()
    }

    /// Generate random-like values for testing
    pub fn generate_test_values(n: usize) -> Vec<u64> {
        vec![1, 3, 5, 7, 9, 2, 4, 6, 8, 10]
            .into_iter()
            .take(n)
            .collect()
    }

    /// Create a simple circuit for testing
    pub fn create_test_circuit() -> PoneglyphCircuit {
        PoneglyphCircuit {
            db_commitment: Value::known(Fr::from(42)),
            query_result: Value::known(Fr::from(100)),
            range_checks: vec![RangeCheckOp {
                value: Value::known(10),
                threshold: 20,
                u: 256,
            }],
            sorts: vec![],
            group_bys: vec![],
            joins: vec![],
            aggregations: vec![],
        }
    }

    /// Helper to create aggregation operation
    pub fn create_aggregation_op(
        group_keys: Vec<u64>,
        values: Vec<u64>,
        agg_type: AggregationType,
    ) -> AggregationOp {
        AggregationOp {
            group_keys,
            values,
            agg_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;

    #[test]
    fn test_generate_sorted_values() {
        let values = generate_sorted_values(5, 0);
        assert_eq!(values, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_create_test_circuit() {
        let circuit = create_test_circuit();
        assert_eq!(circuit.range_checks.len(), 1);
    }
}

