/// Circuit constants and configuration values

/// Maximum number of 8-bit chunks for 64-bit decomposition
pub const MAX_CHUNKS: usize = 8;

/// Lookup table size for range checks
pub const LOOKUP_TABLE_SIZE: u64 = 256;

/// Default threshold for range checks
pub const DEFAULT_RANGE_THRESHOLD: u64 = 256;

/// Maximum circuit size (approximate)
pub const MAX_CIRCUIT_SIZE: usize = 1 << 20;

/// Number of advice columns in circuit configuration
pub const NUM_ADVICE_COLUMNS: usize = 15;

/// Number of fixed columns in circuit configuration
pub const NUM_FIXED_COLUMNS: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert!(MAX_CHUNKS > 0);
        assert!(LOOKUP_TABLE_SIZE > 0);
        assert!(NUM_ADVICE_COLUMNS > 0);
        assert!(NUM_FIXED_COLUMNS > 0);
    }
}
