# Contributing to Role System

Thank you for your interest in contributing to Role System! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to the Contributor Covenant Code of Conduct. Please read our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a new branch for your feature/fix
4. Make your changes
5. Run tests and ensure they pass
6. Submit a pull request

## Development Workflow

### Setting Up Development Environment

1. Install Rust (latest stable)
2. Clone the repository
3. Run `cargo test` to verify everything works

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --test integration_tests

# Run benchmarks (with nightly rust)
cargo +nightly bench
```

### Code Style

- Follow Rust standard formatting (run `cargo fmt`)
- Use `cargo clippy` to catch common mistakes
- Write comprehensive doc comments
- Follow the project's architecture patterns

### Documentation

- Update docs when adding/modifying features
- Include examples in doc comments
- Keep README.md in sync with changes

## Feature Development

### Adding New Features

1. Open an issue describing the feature
2. Discuss implementation approach
3. Write tests first (TDD approach)
4. Implement the feature
5. Update documentation
6. Submit PR

### Performance Considerations

- Use benchmarks to validate performance impact
- Consider concurrent access patterns
- Optimize critical paths when necessary

## Pull Request Process

1. Update documentation
2. Add tests for new features
3. Run the full test suite
4. Update CHANGELOG.md
5. Submit PR with clear description

## License

By contributing, you agree that your contributions will be licensed under both MIT and Apache 2.0 licenses.
