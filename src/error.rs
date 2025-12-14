/// Custom error types for the PoneglyphDB library

use std::fmt;

/// Main error type for PoneglyphDB operations
#[derive(Debug, Clone)]
pub enum PoneglyphError {
    /// Circuit synthesis error
    Synthesis(String),
    /// Invalid input data error
    InvalidInput(String),
    /// Validation error
    Validation(String),
    /// Serialization/deserialization error
    Serialization(String),
    /// Configuration error
    Configuration(String),
}

impl fmt::Display for PoneglyphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoneglyphError::Synthesis(msg) => write!(f, "Synthesis error: {}", msg),
            PoneglyphError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            PoneglyphError::Validation(msg) => write!(f, "Validation error: {}", msg),
            PoneglyphError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            PoneglyphError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for PoneglyphError {}

/// Result type alias for PoneglyphDB operations
pub type PoneglyphResult<T> = Result<T, PoneglyphError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PoneglyphError::InvalidInput("test error".to_string());
        assert!(err.to_string().contains("Invalid input"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_error_types() {
        let errors = vec![
            PoneglyphError::Synthesis("circuit error".to_string()),
            PoneglyphError::InvalidInput("bad input".to_string()),
            PoneglyphError::Validation("validation failed".to_string()),
            PoneglyphError::Serialization("serde error".to_string()),
            PoneglyphError::Configuration("config error".to_string()),
        ];

        for err in errors {
            assert!(!err.to_string().is_empty());
        }
    }
}

