/// Validation helper functions for circuit operations

use crate::error::{PoneglyphError, PoneglyphResult};

/// Validate that two slices have the same length
pub fn validate_equal_length<T, U>(
    a: &[T],
    b: &[U],
    error_msg: &str,
) -> PoneglyphResult<()> {
    if a.len() != b.len() {
        return Err(PoneglyphError::Validation(format!(
            "{}: lengths do not match ({} vs {})",
            error_msg,
            a.len(),
            b.len()
        )));
    }
    Ok(())
}

/// Validate that a slice is not empty
pub fn validate_not_empty<T>(slice: &[T], error_msg: &str) -> PoneglyphResult<()> {
    if slice.is_empty() {
        return Err(PoneglyphError::Validation(format!("{}: slice is empty", error_msg)));
    }
    Ok(())
}

/// Validate that a value is within a range [min, max)
pub fn validate_range(value: u64, min: u64, max: u64, error_msg: &str) -> PoneglyphResult<()> {
    if value < min || value >= max {
        return Err(PoneglyphError::Validation(format!(
            "{}: value {} is not in range [{}, {})",
            error_msg, value, min, max
        )));
    }
    Ok(())
}

/// Validate that keys are sorted (non-decreasing)
pub fn validate_sorted<T: Ord>(keys: &[T], error_msg: &str) -> PoneglyphResult<()> {
    for i in 1..keys.len() {
        if keys[i] < keys[i - 1] {
            return Err(PoneglyphError::Validation(format!(
                "{}: keys are not sorted at index {}",
                error_msg, i
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_equal_length() {
        assert!(validate_equal_length(&[1, 2], &[3, 4], "test").is_ok());
        assert!(validate_equal_length(&[1], &[3, 4], "test").is_err());
    }

    #[test]
    fn test_validate_not_empty() {
        assert!(validate_not_empty(&[1, 2], "test").is_ok());
        assert!(validate_not_empty(&[] as &[i32], "test").is_err());
    }

    #[test]
    fn test_validate_range() {
        assert!(validate_range(5, 0, 10, "test").is_ok());
        assert!(validate_range(10, 0, 10, "test").is_err());
        assert!(validate_range(15, 0, 10, "test").is_err());
    }

    #[test]
    fn test_validate_sorted() {
        assert!(validate_sorted(&[1, 2, 3], "test").is_ok());
        assert!(validate_sorted(&[3, 2, 1], "test").is_err());
    }
}

