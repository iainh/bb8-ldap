# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-02-05

### Fixed
- Fixed test using incorrect default OpenLDAP admin password (`adminpassword` instead of `admin`)
- Fixed race condition in test where `has_broken()` check occurred before channel close propagated

## [0.4.0] - 2026-02-05

### Changed
- **Breaking:** Consolidated to single validating `new()` constructor that validates URL scheme
- `new()` now returns `Result<Self, LdapError>` instead of `Self`
- Reject unsupported URL schemes (only `ldap://` and `ldapi://` are accepted)

## [0.3.0] - 2025-10-08

### Added
- Initial public release
- `LdapConnectionManager` implementing `bb8::ManageConnection`
- Support for bind credentials
- Configurable validation timeout and search
- Configurable connection timeout
- TLS feature flags: `tls-native`, `tls-rustls-aws-lc-rs`, `tls-rustls-ring`

[0.4.1]: https://github.com/iainh/bb8-ldap/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/iainh/bb8-ldap/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/iainh/bb8-ldap/releases/tag/v0.3.0
