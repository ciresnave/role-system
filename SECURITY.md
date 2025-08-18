# Security Policy

## Supported Versions

Currently supported versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Security Updates

- Security patches are released as soon as possible
- Updates follow semantic versioning for backwards compatibility
- Critical vulnerabilities may receive expedited releases

## Reporting a Vulnerability

To report a security vulnerability:

1. Do NOT create a public GitHub issue
2. Email <security@ciresnave.dev> with details
3. Include steps to reproduce the vulnerability
4. Wait for acknowledgment (within 48 hours)

## Security Response Process

1. Acknowledgment within 48 hours
2. Assessment and validation within 7 days
3. Fix development and testing
4. Security advisory publication
5. Patch release

## Best Practices

When using Role System:

1. Keep dependencies up to date
2. Use `cargo audit` regularly
3. Follow principle of least privilege
4. Enable audit logging in production
5. Review permission assignments regularly

## Security Features

Role System includes several security features:

- Permission validation and sanitization
- Audit logging capabilities
- Secure default configurations
- Thread-safe operations
- Input validation and sanitization

## Known Issues

Known security issues are tracked in our security advisories:
[Security Advisories](https://github.com/ciresnave/role-system/security/advisories)

## Security Architecture

### Permission Model

- All permissions deny by defaultault
- Explicit permission grants required
- Hierarchical role inheritance
- Context-based permission evaluation

### Authentication

Role System does not handle authentication directly.
Integrate with a dedicated authentication system.

### Authorization

- Fine-grained permission control
- Resource-level access control
- Context-aware permission checks
- Role hierarchy enforcement

## Secure Development

Our security practices include:

- Regular dependency audits
- Static code analysis
- Continuous integration testing
- Security-focused code review
- Regular security updates

## Third-Party Audits

We welcome third-party security audits.
Contact us for audit coordination.
