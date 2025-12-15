[![Rust](https://github.com/nzengi/zkp-query/actions/workflows/rust.yml/badge.svg)](https://github.com/nzengi/zkp-query/actions/workflows/rust.yml)

# PoneglyphDB

A zero-knowledge database proof system implementing SQL query verification using Halo2 proofs. This project provides cryptographic proofs for database queries including JOIN, GROUP BY, and aggregation operations.

## ⚠️ License

**PROPRIETARY SOFTWARE - ALL RIGHTS RESERVED**

This software is proprietary and confidential. Unauthorized copying, modification, distribution, or use of this software, via any medium, is strictly prohibited without the express written permission of the copyright holder.

**Commercial License Required**

This software is available under a commercial license. For licensing inquiries, please contact the repository owner.

**Copyright © 2024. All rights reserved.**

## Features

- **Range Check Gate**: 8-bit decomposition and comparison operations
- **Sort Gate**: Verifies sorted arrays using Grand Product Argument
- **Group-By Gate**: Verifies group boundaries in sorted data
- **Join Gate**: Inner join verification with match/miss flags and deduplication
- **Aggregation Gate**: SUM, COUNT, MAX, MIN operations within groups

## Architecture

The circuit is built using Halo2's PLONKish arithmetization and implements the following gates:

- **Range Check Gate** (Section 4.1): Decomposes 64-bit numbers into 8-bit chunks and verifies `x < t` comparisons
- **Sort Gate** (Section 4.2): Verifies sorted arrays and permutations using Grand Product Argument
- **Group-By Gate** (Section 4.3): Verifies group boundaries using inverse element constraints
- **Join Gate** (Section 4.4): Performs inner join verification with key comparison and deduplication
- **Aggregation Gate** (Section 4.5): Implements aggregation operations (SUM, COUNT, MAX, MIN)

## Requirements

- Rust 1.70+ (edition 2021)
- Cargo

## Dependencies

- `halo2_proofs = "0.3.1"` - Halo2 proof system
- `pasta_curves = "0.5"` - Pasta curve implementation
- `ff = "0.13"` - Finite field traits
- `group = "0.13"` - Group traits
- `rand = "0.9"` - Random number generation
- `serde = "1.0"` - Serialization support

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

Run specific test suites:

```bash
# Range Check tests
cargo test --test range_check_tests

# Sort Gate tests
cargo test --test sort_tests

# Group-By tests
cargo test --test group_by_tests

# Join Gate tests
cargo test --test join_tests

# Aggregation tests
cargo test --test aggregation_tests
```

## Project Structure

```
src/
├── circuit/
│   ├── config.rs      # Circuit configuration and column allocation
│   ├── range_check.rs # Range Check Gate implementation
│   ├── sort.rs        # Sort Gate implementation
│   ├── group_by.rs    # Group-By Gate implementation
│   ├── join.rs        # Join Gate implementation
│   └── aggregation.rs # Aggregation Gate implementation
├── lib.rs             # Library entry point
└── main.rs            # Binary entry point
```

## Contributing

We welcome contributions from the community! However, please note that this is a proprietary project with commercial licensing.

### Contributors

- [nzengi](https://github.com/nzengi) - Core contributor

### How to Contribute

1. **Fork the repository** (if you have access)
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes** following the existing code style
4. **Add tests** for new functionality
5. **Ensure all tests pass** (`cargo test`)
6. **Commit your changes** (`git commit -m 'Add some amazing feature'`)
7. **Push to the branch** (`git push origin feature/amazing-feature`)
8. **Open a Pull Request**

### Contribution Guidelines

- Follow Rust style guidelines and use `rustfmt`
- Write comprehensive tests for new features
- Update documentation for user-facing changes
- Ensure all tests pass before submitting PRs
- Keep commits focused and well-documented

### Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain code quality and documentation

## Security

This software implements cryptographic proofs. Please report security vulnerabilities responsibly by contacting the repository maintainers directly.

## Disclaimer

This software is provided "as is" without warranty of any kind. The authors and contributors are not responsible for any damages arising from the use of this software.

## Contact

For questions, licensing inquiries, or security issues, please contact the repository owner.

---

**Note**: This project implements concepts from the PoneglyphDB research paper. For academic references, please consult the original paper.
