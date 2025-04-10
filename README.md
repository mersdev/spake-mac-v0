# Secure Payload Encryption System with SPAKE2+ Protocol

This Spring Boot application implements a comprehensive secure communication system featuring SPAKE2+ protocol integration and secure payload encryption with MAC chaining. The system provides a robust framework for authenticated key exchange and secure message transmission between devices and vehicles.

## Overview

The system consists of two main components:

1. **SPAKE2+ Protocol Implementation**
   - Secure Password-Based Authenticated Key Exchange
   - Device and Vehicle authentication
   - Cryptographic salt and key derivation
   - Evidence-based verification

   ![SPAKE2+ Protocol Flow](src/test/resources/Spake2Plus%20Presentation.png)
   *Figure 1: SPAKE2+ Protocol Flow Diagram showing the four-step authentication process between Vehicle OEM and Device/SBOD*

2. **Secure Payload System**
   - AES encryption with BouncyCastle provider
   - MAC (Message Authentication Code) chaining
   - Request/Response payload handling
   - Sequential message integrity

## Technical Stack

- Spring Boot
- Java
- Gradle
- BouncyCastle Provider for Cryptographic Operations

## Key Components

### SPAKE2+ Protocol Services

1. **Spake2PlusDeviceService**
   - Implements device-side SPAKE2+ protocol
   - Handles password-based key generation
   - Processes authentication requests and responses
   - Generates and verifies cryptographic evidence

2. **Spake2PlusVehicleService**
   - Implements vehicle-side SPAKE2+ protocol
   - Manages authentication challenges
   - Handles key exchange and verification
   - Processes device responses

### Secure Payload Services

1. **PayloadEncryptionService**
   - Request payload encryption
   - MAC generation and chaining
   - AES-CBC encryption
   - ISO/IEC 9797-1 padding

2. **PayloadDecryptionService**
   - Secure payload decryption
   - MAC verification
   - Padding validation
   - Chain integrity verification

3. **PayloadResponseEncryptionService**
   - Response-specific encryption
   - Specialized MAC handling
   - Response counter management

4. **PayloadResponseDecryptionService**
   - Response payload decryption
   - Response MAC verification
   - Response chain validation

## Security Features

### SPAKE2+ Protocol Security

- Elliptic Curve Cryptography (NIST P-256)
- Password-based authentication
- Secure key derivation (SCrypt)
- Cryptographic evidence exchange
- Protection against man-in-the-middle attacks

### Payload Security

- AES-CBC encryption (16-byte keys)
- CMAC-AES-128 for message authentication
- MAC chaining for sequential integrity
- Secure padding management
- Input validation and sanitization

## Getting Started

### Prerequisites

- Java 17 or higher
- Gradle

### Building the Project

```bash
./gradlew build
```

### Running the Application

```bash
./gradlew bootRun
```

## Testing

The application includes comprehensive test coverage:

### SPAKE2+ Protocol Tests
- Full protocol flow integration tests
- Device and vehicle authentication tests
- Evidence verification tests
- Key derivation tests

### Payload System Tests
- Encryption/decryption cycle tests
- MAC chaining verification
- Binary and text payload handling
- Block size edge cases
- Invalid input handling

Run tests using:

```bash
./gradlew test
```

## Technical Specifications

### SPAKE2+ Protocol
- Curve: NIST P-256 (secp256r1)
- Key Size: 256-bit
- Hash Function: SHA-256
- MAC Algorithm: CMAC-AES-128
- KDF: HKDF with SHA-256

### Protocol Implementation Listings

1. **Password Generation and Processing**
   - Listing 18-1: Server Password Generation and Scrypt Output
   - Processes password and cryptographic salt
   - Generates Scrypt output (z) split into z0 and z1

2. **Public Point Generation**
   - Listing 18-2: Vehicle-side Public Point Generation
   - Listing 18-3: Device-side Public Point Generation
   - Generates random scalars and computes public points
   - Implements point multiplication and addition operations

3. **Shared Secret Computation**
   - Listing 18-4: Vehicle-side Computation
   - Listing 18-5: Device-side Computation
   - Calculates shared secret Z and V values
   - Derives confirmation key (CK) and session key (SK)

4. **Key Derivation and Evidence**
   - Listing 18-6: Derivation of Evidence Keys (K1, K2)
   - Listing 18-7: Vehicle-side Evidence Computation
   - Listing 18-8: Device-side Evidence Computation
   - Listing 18-9: Derivation of System Keys
   - Implements HKDF for key derivation
   - Generates and verifies cryptographic evidence

### Payload Encryption
- Encryption: AES-CBC
- Key Size: 128-bit
- MAC: CMAC-AES-128 (8-byte output)
- Padding: ISO/IEC 9797-1 method 2
- Counter Range: 1-255

## Security Considerations

- Implements secure key exchange protocol
- Ensures message integrity and authenticity
- Maintains sequential message integrity
- Protects against replay attacks
- Validates all cryptographic parameters
- Implements proper error handling