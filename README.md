# SPAKE2+ Protocol Implementation

This Spring Boot application implements the SPAKE2+ protocol for secure device-to-vehicle authentication. The implementation provides a robust framework for establishing secure communication channels between devices and vehicles using the SPAKE2+ password-authenticated key exchange protocol.

## Overview

The SPAKE2+ protocol is a password-authenticated key exchange protocol that allows two parties to establish a shared secret key based on a low-entropy password, without exposing the password to offline dictionary attacks. This implementation is specifically designed for secure authentication between devices and vehicles.

## Technical Stack

- Spring Boot 3.4.4
- Java
- Gradle

## Key Components

### Core Services

1. **Spake2PlusService**
   - Core implementation of the SPAKE2+ protocol
   - Handles the cryptographic operations and protocol flow

2. **Spake2PlusDeviceService**
   - Manages device-side protocol operations
   - Handles SPAKE2+ request processing
   - Implements device-specific security measures

3. **Spake2PlusVehicleService**
   - Manages vehicle-side protocol operations
   - Creates and processes SPAKE2+ requests
   - Implements vehicle-specific security features

## Features

- Full SPAKE2+ protocol implementation
- Secure key exchange between devices and vehicles
- Request/Response handling for both device and vehicle endpoints
- Robust error handling for invalid curve points and other security concerns
- Integration tests covering the complete protocol flow

## Getting Started

### Prerequisites

- Java 17 or higher
- Gradle 8.13 or higher

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

- Unit tests for both device and vehicle services
- Integration tests for full protocol flow
- Security validation tests

Run tests using:

```bash
./gradlew test
```

## API Documentation

The application exposes RESTful endpoints for SPAKE2+ protocol operations. Detailed API documentation is available through Spring Web.

### Reference Documentation

- [Spring Boot Documentation](https://docs.spring.io/spring-boot/3.4.4/reference/web/servlet.html)
- [Building REST services with Spring](https://spring.io/guides/tutorials/rest/)

## Security Considerations

- Implements secure password-authenticated key exchange
- Protects against offline dictionary attacks
- Validates curve points to prevent invalid curve attacks
- Implements proper error handling for security-related issues

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.