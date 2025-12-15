## Unreleased

- Added various documentation and configuration files.
- Added utils helpers.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Issue templates for bug reports, feature requests, performance issues, and documentation
- Pull request template for standardized contributions
- Dependabot configuration for automated dependency updates
- CHANGELOG.md for tracking project changes
- FUNDING.yml for GitHub Sponsors support

## [0.1.0] - 2024-12-01

### Added
- **Range Check Gate**: 8-bit decomposition and comparison operations for verifying `x < t` comparisons
- **Sort Gate**: Verifies sorted arrays using Grand Product Argument
- **Group-By Gate**: Verifies group boundaries in sorted data using inverse element constraints
- **Join Gate**: Inner join verification with match/miss flags and deduplication
- **Aggregation Gate**: SUM, COUNT, MAX, MIN operations within groups
- **Recursive Proof Composition**: Support for recursive proof composition using Halo2 cycle curves (Pallas/Vesta)
- **SQL Parser and Compiler**: Module for parsing and compiling SQL queries
- **Optimization Module**: Production improvements and optimizations
- **TPCH Benchmark Suite**: Benchmark implementation for performance testing
- **Database Module**: Database commitment using IPA (Inner Product Argument)
- **Prover Module**: Halo2-based proof generation and verification
- Comprehensive test suites for all circuit gates:
  - Range check tests
  - Sort gate tests
  - Group-by tests
  - Join gate tests
  - Aggregation tests
- Benchmark configuration in Cargo.toml
- Core dependencies: halo2_proofs, pasta_curves, serde, and related crates

### Changed
- Improved core modules documentation
- Updated circuit module documentation and comments
- Refactored aggregation.rs for clarity and consistency
- Refactored group_by.rs comments for improved clarity

### Documentation
- Enhanced README.md with comprehensive project documentation
- Added architecture documentation
- Documented all circuit gates and their implementations
- Added contributing guidelines
- Included project structure documentation

---

## Types of Changes

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

