# Schnorr Zero-Knowledge DLOG Proof



A Rust implementation of the Non-interactive Schnorr Zero-Knowledge Discrete Logarithm (DLOG) Proof scheme with a Fiat-Shamir transformation.

## Version

Current version: 0.2.0

### Changelog

#### v0.2.0
- Added comprehensive test suite
- Implemented logging with env_logger
- Added GitHub Actions CI/CD pipeline
- Added code coverage reporting

#### v0.1.0
- Initial implementation of Schnorr ZK DLOG Proof
- Basic proof generation and verification
- Fiat-Shamir transformation

## Overview

This implementation provides a zero-knowledge proof system that allows a prover to demonstrate knowledge of a discrete logarithm without revealing the actual value. The implementation uses the secp256k1 elliptic curve through the k256 crate.

## Features

- Non-interactive Schnorr ZK proof generation and verification
- Secure random number generation
- Fiat-Shamir transformation for non-interactivity
- Comprehensive test suite
- Logging support

## Implementation Details

### Core Components

1. `DLogProof` struct:
   - `t`: Commitment value (ProjectivePoint)
   - `s`: Response value (Scalar)

2. Main Functions:
   - `hash_points`: Implements the Fiat-Shamir transformation
   - `prove`: Generates a zero-knowledge proof
   - `verify`: Verifies a zero-knowledge proof
   - `generate_random_scalar`: Generates cryptographically secure random values

### Security Properties

The implementation ensures:
- Zero-knowledge: The proof reveals nothing about the secret value
- Soundness: Invalid proofs are rejected
- Completeness: Valid proofs are accepted

## Dependencies

```toml
k256 = { version = "0.13.1", features = ["arithmetic"] }
rand_core = "0.6.4"
sha2 = "0.10.7"
env_logger = "0.11.5"
log = "0.4.22"
tracing = { version = "0.1.40", features = ["log"] }
```

## Usage

### Building the Project

```bash
cargo build
```

### Running the Example

```bash
# Run with default info logging
cargo run

# Run with debug logging
RUST_LOG=debug cargo run
```

### Running Tests

```bash
cargo test
```

## Test Coverage

The implementation includes extensive tests covering:

1. Hash Point Generation:
   - Basic functionality
   - Different session IDs
   - Different participant IDs
   - Empty point lists

2. Proof Generation and Verification:
   - Basic prove/verify cycle
   - Wrong session ID handling
   - Wrong participant ID handling
   - Wrong public key handling
   - Multiple proofs for same secret

3. Random Scalar Generation:
   - Uniqueness
   - Range verification

4. Tamper Resistance:
   - Modified response value
   - Modified commitment value
   - Different tampering scenarios

## Logging

The implementation uses the `log` crate with `env_logger` for configurable logging levels:
- INFO: General execution information
- DEBUG: Detailed values and timing information

## Security Considerations

This implementation is for educational purposes. While it implements the core cryptographic operations correctly, it has not been audited for production use.

## Documentation

### Generating Documentation

To generate the documentation locally, run:

```bash
# Make the script executable
chmod +x scripts/generate_docs.sh

# Generate documentation
./scripts/generate_docs.sh
```

The documentation will be generated in the `docs` directory. You can view it by opening `docs/index.html` in your browser.