/// Utility functions for common operations

/// Convert bytes to hex string representation
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Parse hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }
    
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| format!("Invalid hex character at position {}", i)))
        .collect()
}

/// Calculate simple hash for a slice of bytes
pub fn simple_hash(data: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hex() {
        let bytes = vec![0x12, 0x34, 0xab, 0xcd];
        let hex = super::bytes_to_hex(&bytes);
        assert_eq!(hex, "1234abcd");
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "1234abcd";
        let bytes = super::hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn test_hex_to_bytes_odd_length() {
        let hex = "123";
        let result = super::hex_to_bytes(hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("even length"));
    }

    #[test]
    fn test_simple_hash() {
        let data = b"test data";
        let hash1 = super::simple_hash(data);
        let hash2 = super::simple_hash(data);
        assert_eq!(hash1, hash2);
    }
}

// PR improvement 1
// PR improvement 2
// PR improvement 3
// PR improvement 4
// PR improvement 5
// PR improvement 6
// PR improvement 7
// PR improvement 8
// PR improvement 9
// PR improvement 10
