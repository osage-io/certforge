# CertForge

Simple Binary for working with TLS Certificates. CertForge simplifies the creation and analysis of SSL/TLS certificates, Certificate Signing Requests (CSRs), and private keys.

## Features

- **Certificate Generation**: Create CSRs for submission to Certificate Authorities
- **Self-Signed Certificates**: Generate self-signed certificates for development and testing
- **Subject Alternative Names (SANs)**: Add multiple domain names to a single certificate
- **Key Customization**: Choose RSA key sizes (2048, 3072, or 4096 bits)
- **Certificate Decoding**: Analyze existing certificates, CSRs, and private keys
- **Output Directory Support**: Save generated files to specific directories
- **Interactive Interface**: Guided prompts for all required certificate information

## Installation

### Prerequisites

- Go 1.13 or higher

### Building from Source

Clone the repository and build using the included Makefile:

```bash
git clone https://github.com/osage-io/certforge.git
cd certforge
make
```

The binary will be created in the current directory.

### Manual Build

```bash
go build -o certforge
```

## Usage

### Generate a Certificate

To generate a certificate interactively:

```bash
./certforge
```

This will prompt you for all necessary certificate information and create:
- A private key (.key)
- A Certificate Signing Request (.csr)

### Generate a Self-Signed Certificate

To generate a self-signed certificate:

```bash
./certforge -s
```

This will create all the files above plus a self-signed certificate (.crt).

### Specify Output Directory

To save files to a specific directory:

```bash
./certforge -o=/path/to/certs
```

The directory will be created if it doesn't exist.

### Specify Certificate Validity Period

For self-signed certificates, you can specify how long they should be valid:

```bash
./certforge -s -days=730  # Valid for 2 years
```

### Decode Certificate Files

To analyze existing certificate files:

```bash
./certforge --decode cert.crt  # Decode a certificate
./certforge --decode cert.csr  # Decode a CSR
./certforge --decode cert.key  # Decode a private key
```

### Complete Examples

1. Generate a self-signed certificate with a 2-year validity period in a specific directory:
   ```bash
   ./certforge -s -days=730 -o=/path/to/certs
   ```

2. Create a CSR for submission to a CA:
   ```bash
   ./certforge
   ```

3. Decode an existing certificate:
   ```bash
   ./certforge --decode mycert.crt
   ```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-h`, `--help` | Show help information and exit |
| `-v`, `--version` | Show version information |
| `-s` | Create a self-signed certificate instead of just a CSR |
| `-days=<number>` | Validity period in days for self-signed certificates (default: 365) |
| `-o=<directory>` | Output directory for generated files (default: current directory) |
| `--decode <file>` | Decode and display information about a certificate, CSR, or key file |

## Output Files

- `<prefix>.key` - Private key file
- `<prefix>.csr` - Certificate Signing Request file
- `<prefix>.crt` - Self-signed certificate file (if requested)

By default, the prefix is "cert", but you can specify a custom prefix during the interactive prompts.

## Using with OpenSSL

CertForge's `--decode` option provides a friendlier alternative to OpenSSL commands, but you can still use OpenSSL for additional functionality:

```bash
# View certificate details with OpenSSL
openssl x509 -in cert.crt -text -noout

# View CSR details with OpenSSL
openssl req -in cert.csr -text -noout
```

## License

[Mozilla Public License Version 2.0](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
