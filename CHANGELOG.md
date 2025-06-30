# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2025-06-30

### Fixed

- **Authenticator Assertion Handling**: Fixed issue where `getAssertion()` was not properly handling requests without
  specific credential IDs
- **Improved Test Coverage**: Enhanced unit tests for Authenticator and Base64Converter classes, refactored tests for
  repositories

## [1.2.0] - 2025-06-30

### Added

- **Testing Framework**: Complete PHPUnit testing infrastructure with comprehensive test coverage
    - Unit tests for all core components (Authenticator, Credential, CredentialFactory, Base64Converter)
    - Integration tests for repository implementations (FileRepository, InMemoryRepository)
    - Feature tests for real-world WebAuthn server flows (WebAuthn.io, Yubico, Lubu.ch, Quado.io)
    - PHPUnit configuration file (`phpunit.xml.dist`) with organized test suites
    - Test bootstrap file for proper test environment setup
- **InMemoryRepository**: New in-memory credential storage implementation for testing and temporary use
- **Strict Type Declarations**: Added `declare(strict_types=1)` to all PHP files for better type safety
- **Development Dependencies**: Added Guzzle HTTP client and PHPUnit as development dependencies

### Changed

- **Enhanced Documentation**: Significantly expanded README.md with:
    - Detailed usage examples for registration and authentication
    - Comprehensive explanation of base64url vs base64 encoding
    - Updated examples with better server integration patterns
    - More detailed API documentation with parameter explanations
- **Improved Base64 Handling**: Enhanced base64url encoding/decoding methods in Authenticator class
- **Updated .gitignore**: Added common development files and directories to ignore list

### Fixed

- **Code Style**: Consistent formatting and code style improvements across the codebase
- **Example Cleanup**: Removed debug code and improved example scripts for better clarity

## [1.1.0] - 2023-12-28

### Added

- **Base64url Encoding Utilities**: Helper functions for base64url encoding/decoding
    - `base64Normal2Url()`: Convert standard base64 to base64url format
    - `base64Url2Normal()`: Convert base64url to standard base64 format
    - Support for recursive array processing

### Changed

- **Updated Documentation**: Enhanced README.md with detailed usage examples and server integration guides
- **Improved Examples**: Updated example scripts to demonstrate base64url handling
- **WebAuthn API Reference**: Added reference to official Web Authentication API documentation

### Fixed

- **Encoding Consistency**: Fixed base64url encoding issues in example scripts
- **Server Compatibility**: Improved compatibility with various WebAuthn server implementations

## [1.0.0] - 2023-12-28

### Added

- Initial release of WebAuthn Emulator
- Core WebAuthn registration (attestation) and authentication (assertion) functionality
- ES256 algorithm support for public key credentials
- 'none' attestation format implementation
- Flexible credential repository system with FileRepository implementation
- Comprehensive examples for popular WebAuthn servers
- MIT license

### Supported Features

- WebAuthn registration and authentication flows
- CBOR encoding for WebAuthn protocol compliance
- OpenSSL-based cryptography for key generation and signing
- Automatic sign counter management for replay attack prevention
- Interface-based architecture for extensibility

[1.2.1]: https://github.com/vadimpronin/webauthn-emulator/compare/1.2.0...1.2.1

[1.2.0]: https://github.com/vadimpronin/webauthn-emulator/compare/1.1.0...1.2.0

[1.1.0]: https://github.com/vadimpronin/webauthn-emulator/compare/1.0.0...1.1.0

[1.0.0]: https://github.com/vadimpronin/webauthn-emulator/releases/tag/1.0.0
