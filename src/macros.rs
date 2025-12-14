/// Helper macros for circuit operations

/// Macro to create a range check operation
#[macro_export]
macro_rules! range_check_op {
    ($value:expr, $threshold:expr, $u:expr) => {
        $crate::RangeCheckOp {
            value: halo2_proofs::circuit::Value::known($value),
            threshold: $threshold,
            u: $u,
        }
    };
}

/// Macro to create an aggregation operation
#[macro_export]
macro_rules! aggregation_op {
    ($group_keys:expr, $values:expr, $agg_type:expr) => {
        $crate::AggregationOp {
            group_keys: $group_keys,
            values: $values,
            agg_type: $agg_type,
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{AggregationOp, AggregationType, RangeCheckOp};

    #[test]
    fn test_range_check_op_macro() {
        let op = range_check_op!(10u64, 20u64, 256u64);
        assert_eq!(op.threshold, 20);
        assert_eq!(op.u, 256);
    }

    #[test]
    fn test_aggregation_op_macro() {
        let op = aggregation_op!(
            vec![1, 2, 3],
            vec![10, 20, 30],
            AggregationType::Sum
        );
        assert_eq!(op.group_keys.len(), 3);
        assert_eq!(op.values.len(), 3);
    }
}

