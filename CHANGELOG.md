# Change Log
All notable changes to this project will be documented in this file. This change log follows the conventions of [keepachangelog.com](http://keepachangelog.com/).

## [0.3.0]
### Added
RSA support
Crypto module exposing AES-GCM, RSA, PBKDF2
### Changed
Encryption functionality is now async
Cryptopacks have been moved to their own module
cryptopack/encrypt is now keyword-based for its arguments

## [0.2.2]
### Added
messagepack support for uniformity.random's encrypt and decrypt

## [0.2.1]
### Added
rand-shuffle function to uniformity.random

## [0.2.0]
### Added
JVM and ClojureScript support for AES-GCM encryption with a high-level API

## [0.1.1]
### Changed
- Use goog.crypt in internals.util-js in place of base64-js dependency and homebrew hex encode

## [0.1.0]
### Added
JVM and ClojureScript support for cryptographically-random:
- booleans
- bytes
- 32-bit integers
- base64/hex-encoded strings
- UUIDs
- collection samples
- passwords/passphrases

[0.3.0]: https://github.com/skinkade/uniformity/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/skinkade/uniformity/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/skinkade/uniformity/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/skinkade/uniformity/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/skinkade/uniformity/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/skinkade/uniformity/releases/tag/v0.1.0
