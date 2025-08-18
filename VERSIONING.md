# Versioning and API Stability Policy

## Semantic Versioning

Role System follows [Semantic Versioning 2.0.0](https://semver.org/). In summary:

- MAJOR version changes (x.0.0) indicate incompatible API changes
- MINOR version changes (0.x.0) indicate new functionality in a backwards-compatible manner
- PATCH version changes (0.0.x) indicate backwards-compatible bug fixes

## API Stability Guarantees

### Stable APIs (1.0.0 and later)

Once Role System reaches 1.0.0:

- Public APIs will maintain backwards compatibility within the same major version
- Breaking changes will be clearly documented in the changelog
- Deprecated features will be marked with `#[deprecated]` for at least one minor version before removal
- Any breaking changes will result in a major version increment

### Current Status (Pre-1.0.0)

While in 0.x.x versions:

- Minor version increments may contain breaking changes
- APIs are considered "unstable" and may change between releases
- Changes will be documented in the changelog
- We aim to minimize breaking changes but cannot guarantee API stability

### Stability Levels

APIs are marked with stability levels:

- **Stable**: Covered by semantic versioning guarantees
- **Unstable**: May change in minor versions (marked with `#[unstable]`)
- **Experimental**: May change or be removed (marked with appropriate attributes)

### Minimum Supported Rust Version (MSRV)

- The MSRV is clearly documented in the changelog
- MSRV changes require a minor version bump
- We aim to support the last 3 stable Rust releases

## Breaking Changes

The following are considered breaking changes:

- Removing or renaming public APIs
- Adding trait bounds to public interfaces
- Changing function signatures
- Modifying type definitions
- Changing error types or variants
- Removing feature flags

## Feature Flags Stability

Feature flags are categorized as:

- **Stable**: Will remain available with consistent behavior
- **Unstable**: May change behavior or be removed
- **Experimental**: May be removed without notice

## Long-term Support (LTS)

- LTS versions will be designated in major releases
- LTS versions receive security updates for 1 year
- Critical bug fixes may be backported to LTS versions

## API Migration Guide

When breaking changes are necessary:

1. The change will be announced in advance
2. Migration guides will be provided
3. Tooling for automated updates may be provided
4. The old API may be maintained in a compatibility layer

## Deprecation Process

1. Feature is marked as deprecated with `#[deprecated]`
2. Documentation is updated with migration path
3. Feature remains for at least one minor version
4. Removal occurs in next major version

## Security Updates

- Security fixes may bypass usual deprecation process
- Critical updates will be released as soon as possible
- Security advisories will be published via cargo-audit

## Version Support Matrix

| Version Range | Status | Support Level | End-of-Life |
|--------------|---------|---------------|-------------|
| 0.x.x        | Active  | Development   | 1.0.0       |
| 1.x.x        | Future  | Stable        | TBD         |

## Community Input

We value community feedback on API changes:

- Major changes are discussed in GitHub issues
- RFCs may be required for significant changes
- Breaking changes have a discussion period

## Additional Resources

- [CHANGELOG.md](CHANGELOG.md) for version history
- [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
- [Security Policy](SECURITY.md) for security practices
