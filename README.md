# Secure Payload Encryption System

This Spring Boot application implements a robust secure payload encryption system with MAC chaining for secure communication. The implementation provides a comprehensive framework for encrypting and decrypting payloads with message authentication and sequential message integrity.

## Overview

The system implements secure payload encryption using AES with the BouncyCastle provider, featuring MAC (Message Authentication Code) chaining for sequential message integrity. It supports both request and response payload handling with separate encryption services and comprehensive security measures.

## Technical Stack

- Spring Boot
- Java
- Gradle
- BouncyCastle Provider for Cryptographic Operations

## Key Components

### Core Services

1. **PayloadEncryptionService**
   - Handles encryption of request payloads
   - Implements AES encryption with MAC generation
   - Supports MAC chaining for sequential messages

2. **PayloadDecryptionService**
   - Manages decryption of encrypted payloads
   - Validates MAC before decryption
   - Handles MAC chaining verification

3. **PayloadResponseEncryptionService**
   - Specialized service for response payload encryption
   - Implements response-specific security measures
   - Supports response MAC chaining

## Features

- AES encryption for payload security
- MAC generation and validation
- MAC chaining for sequential message integrity
- Support for both request and response payloads
- Comprehensive error handling and input validation
- Padding management for variable-length payloads

## Security Features

- 16-byte encryption keys (KENC) for AES operations
- 16-byte MAC keys (KMAC/KRMAC) for message authentication
- MAC chaining for sequential message integrity
- Padding validation and management
- Comprehensive input validation
- Protection against various cryptographic attacks

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

- Unit tests for encryption and decryption services
- Integration tests for full encryption/decryption cycles
- Edge case testing for various payload sizes
- Security validation tests
- MAC chaining verification tests

Test scenarios include:
- Text and binary payload handling
- MAC chaining across multiple messages
- Block size edge cases
- Invalid input handling
- Empty and null payload cases

Run tests using:

```bash
./gradlew test
```

## Security Considerations

- Implements secure AES encryption
- Ensures message integrity through MAC validation
- Maintains sequential message integrity via MAC chaining
- Validates all cryptographic parameters
- Implements proper error handling for security-related issues

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.