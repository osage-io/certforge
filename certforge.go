// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// version is set during build using -ldflags="-X main.version=v1.x.x"
var version = "development"

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}

// decodeFile decodes and displays information about certificate, CSR, or key files
func decodeFile(filePath string) error {
// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("Error reading file: %v", err)
	}
	
	// Decode PEM
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("Failed to parse PEM block from file")
	}
	
	// Process based on block type
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("Failed to parse certificate: %v", err)
		}
		printCertificateInfo(cert)
		
	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return fmt.Errorf("Failed to parse CSR: %v", err)
		}
		printCSRInfo(csr)
		
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("Failed to parse RSA private key: %v", err)
		}
		printRSAKeyInfo(key)
		
	case "PRIVATE KEY":
		// This might be a PKCS8 key
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("Failed to parse private key: %v", err)
		}
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			printRSAKeyInfo(rsaKey)
		} else {
			return fmt.Errorf("Unsupported private key type")
		}
		
	default:
		return fmt.Errorf("Unsupported PEM block type: %s", block.Type)
	}
	
	return nil
}

// printCertificateInfo displays information about an X.509 certificate
func printCertificateInfo(cert *x509.Certificate) {
	fmt.Println("=== Certificate Information ===\n")
	fmt.Printf("Subject: %s\n", formatName(cert.Subject))
	fmt.Printf("Issuer: %s\n", formatName(cert.Issuer))
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	
	// Display DNS names (Subject Alternative Names)
	if len(cert.DNSNames) > 0 {
		fmt.Println("\nSubject Alternative Names:")
		for _, name := range cert.DNSNames {
			fmt.Printf("  DNS: %s\n", name)
		}
	}
	
	// Check if self-signed
	isSelfSigned := cert.Subject.String() == cert.Issuer.String()
	fmt.Printf("\nSelf-signed: %t\n", isSelfSigned)
	
	// Display key usage
	fmt.Println("\nKey Usage:")
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		fmt.Println("  Digital Signature")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		fmt.Println("  Content Commitment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		fmt.Println("  Key Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		fmt.Println("  Data Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		fmt.Println("  Key Agreement")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		fmt.Println("  Certificate Sign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		fmt.Println("  CRL Sign")
	}
	if cert.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		fmt.Println("  Encipher Only")
	}
	if cert.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		fmt.Println("  Decipher Only")
	}
	
	// Display extended key usage
	if len(cert.ExtKeyUsage) > 0 {
		fmt.Println("\nExtended Key Usage:")
		for _, usage := range cert.ExtKeyUsage {
			switch usage {
			case x509.ExtKeyUsageServerAuth:
				fmt.Println("  Server Authentication")
			case x509.ExtKeyUsageClientAuth:
				fmt.Println("  Client Authentication")
			case x509.ExtKeyUsageCodeSigning:
				fmt.Println("  Code Signing")
			case x509.ExtKeyUsageEmailProtection:
				fmt.Println("  Email Protection")
			case x509.ExtKeyUsageTimeStamping:
				fmt.Println("  Time Stamping")
			case x509.ExtKeyUsageOCSPSigning:
				fmt.Println("  OCSP Signing")
			}
		}
	}
}

// printCSRInfo displays information about a Certificate Signing Request
func printCSRInfo(csr *x509.CertificateRequest) {
	fmt.Println("=== Certificate Signing Request Information ===\n")
	fmt.Printf("Subject: %s\n", formatName(csr.Subject))
	fmt.Printf("Signature Algorithm: %s\n", csr.SignatureAlgorithm)
	
	// Extract DNS names from SANs extension
	var dnsNames []string
	
	for _, ext := range csr.Extensions {
		// OID for subjectAltName extension
		if ext.Id.Equal([]int{2, 5, 29, 17}) {
			var seq asn1.RawValue
			if rest, err := asn1.Unmarshal(ext.Value, &seq); err == nil && len(rest) == 0 {
				if seq.Class == asn1.ClassUniversal && seq.Tag == asn1.TagSequence {
					var rawValues []asn1.RawValue
					if rest, err := asn1.Unmarshal(seq.Bytes, &rawValues); err == nil && len(rest) == 0 {
						for _, rv := range rawValues {
							if rv.Class == 2 && rv.Tag == 2 { // DNS name
								dnsNames = append(dnsNames, string(rv.Bytes))
							}
						}
					}
				}
			}
		}
	}
	
	// Display DNS names
	if len(dnsNames) > 0 {
		fmt.Println("\nSubject Alternative Names:")
		for _, name := range dnsNames {
			fmt.Printf("  DNS: %s\n", name)
		}
	}
	
	// Display signature validity
	err := csr.CheckSignature()
	fmt.Printf("\nSignature Valid: %t\n", err == nil)
	if err != nil {
		fmt.Printf("Signature Error: %v\n", err)
	}
}

// printRSAKeyInfo displays information about an RSA private key
func printRSAKeyInfo(key *rsa.PrivateKey) {
	fmt.Println("=== RSA Private Key Information ===\n")
	fmt.Printf("Key Size: %d bits\n", key.N.BitLen())
	fmt.Printf("Public Exponent: %d\n", key.E)
	
	// Calculate fingerprint of public key
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err == nil {
		fmt.Printf("Public Key Fingerprint (SHA-256): %x\n", sha256.Sum256(pubDER))
	}
	
	// Validate key
	if err := key.Validate(); err != nil {
		fmt.Printf("\nKey Validation Error: %v\n", err)
	} else {
		fmt.Println("\nKey is valid")
	}
}

// formatName converts a Distinguished Name to a readable string
func formatName(name pkix.Name) string {
	var parts []string
	
	if name.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", name.CommonName))
	}
	
	for _, org := range name.Organization {
		parts = append(parts, fmt.Sprintf("O=%s", org))
	}
	
	for _, ou := range name.OrganizationalUnit {
		parts = append(parts, fmt.Sprintf("OU=%s", ou))
	}
	
	for _, country := range name.Country {
		parts = append(parts, fmt.Sprintf("C=%s", country))
	}
	
	for _, province := range name.Province {
		parts = append(parts, fmt.Sprintf("ST=%s", province))
	}
	
	for _, locality := range name.Locality {
		parts = append(parts, fmt.Sprintf("L=%s", locality))
	}
	
	return strings.Join(parts, ", ")
}

// printHelp displays the usage information for CertForge
func printHelp() {
	fmt.Println("CertForge - TLS Certificate Generator")
	fmt.Println("----------------------------------")
	fmt.Println("\nDescription:")
	fmt.Println("  CertForge is a tool for generating SSL/TLS certificates and keys.")
	fmt.Println("  It can create Certificate Signing Requests (CSRs) for submission to a CA")
	fmt.Println("  or generate self-signed certificates for development and testing.")
	
	fmt.Println("\nUsage:")
	fmt.Println("  certforge [options]")
	fmt.Println("  certforge --decode <file>")
	
	fmt.Println("\nOptions:")
	fmt.Println("  -h, --help      Show this help message and exit")
	fmt.Println("  -v, --version   Show version information")
	fmt.Println("  -s              Create a self-signed certificate instead of just CSR")
	fmt.Println("  -days=<number>  Validity period in days for self-signed certificates (default: 365)")
	fmt.Println("  -o=<directory>  Output directory for generated files (default: current directory)")
	fmt.Println("  --decode <file> Decode and display information about a certificate, CSR, or key file")
	
	fmt.Println("\nFeatures:")
	fmt.Println("  - RSA private key generation with customizable key size")
	fmt.Println("  - Certificate Signing Request (CSR) creation")
	fmt.Println("  - Self-signed certificate generation")
	fmt.Println("  - Subject Alternative Names (SANs) support")
	fmt.Println("  - Interactive prompts for all required certificate fields")
	fmt.Println("  - Decoding of certificate, CSR, and key files")
	
	fmt.Println("\nOutput Files:")
	fmt.Println("  - <prefix>.key  Private key file")
	fmt.Println("  - <prefix>.csr  Certificate Signing Request file")
	fmt.Println("  - <prefix>.crt  Self-signed certificate file (if selected)")
	
	fmt.Println("\nExamples:")
	fmt.Println("  # Generate a certificate interactively")
	fmt.Println("  certforge")
	
	fmt.Println("  # Generate a self-signed certificate with 2-year validity")
	fmt.Println("  certforge -s -days=730")
	
	fmt.Println("  # Generate certificates in a specific directory")
	fmt.Println("  certforge -o=/path/to/certs")
	
	fmt.Println("  # Generate a self-signed certificate in a specific directory")
	fmt.Println("  certforge -s -o=/path/to/certs")
	
	fmt.Println("  # Decode and display information about a certificate")
	fmt.Println("  certforge --decode cert.crt")
	
	fmt.Println("  # Decode and display information about a CSR")
	fmt.Println("  certforge --decode cert.csr")
	
	fmt.Println("  # Decode and display information about a private key")
	fmt.Println("  certforge --decode cert.key")
	
	fmt.Println("  # Check the details of a generated certificate using OpenSSL")
	fmt.Println("  openssl x509 -in cert.crt -text -noout")
	
	fmt.Println("  # View a generated CSR using OpenSSL")
	fmt.Println("  openssl req -in cert.csr -text -noout")
}

func main() {
	// Define command-line flags
	helpFlag := flag.Bool("help", false, "Show help information")
	shortHelpFlag := flag.Bool("h", false, "Show help information")
	versionFlag := flag.Bool("version", false, "Show version information")
	shortVersionFlag := flag.Bool("v", false, "Show version information")
	selfSignedFlag := flag.Bool("s", false, "Create a self-signed certificate instead of just CSR")
	daysFlag := flag.Int("days", 365, "Validity period in days for self-signed certificates")
	outputDirFlag := flag.String("o", "", "Output directory for generated files (default: current directory)")
	decodeFlag := flag.String("decode", "", "Decode and display information about a certificate, CSR, or key file")
	
	// Parse command-line flags
	flag.Parse()
	
	// Show help if requested
	if *helpFlag || *shortHelpFlag {
		printHelp()
		return
	}
	
	// Show version if requested
	if *versionFlag || *shortVersionFlag {
		fmt.Printf("CertForge %s\n", version)
		return
	}
	
	// Handle decode mode
	if *decodeFlag != "" {
		if err := decodeFile(*decodeFlag); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	
	fmt.Println("CertForge - TLS Certificate Generator")
	fmt.Println("----------------------------------")

	// Get user input for CSR details
	reader := bufio.NewReader(os.Stdin)

	// Common Name (CN) - typically the domain name
	fmt.Print("Common Name (domain name, e.g. example.com): ")
	commonName, _ := reader.ReadString('\n')
	commonName = strings.TrimSpace(commonName)

	// Organization
	fmt.Print("Organization (e.g. Company Inc): ")
	organization, _ := reader.ReadString('\n')
	organization = strings.TrimSpace(organization)

	// Organizational Unit
	fmt.Print("Organizational Unit (e.g. IT Department): ")
	organizationalUnit, _ := reader.ReadString('\n')
	organizationalUnit = strings.TrimSpace(organizationalUnit)

	// Country
	fmt.Print("Country (2 letter code, e.g. US): ")
	country, _ := reader.ReadString('\n')
	country = strings.TrimSpace(country)

	// State/Province
	fmt.Print("State/Province (e.g. California): ")
	state, _ := reader.ReadString('\n')
	state = strings.TrimSpace(state)

	// Locality/City
	fmt.Print("Locality/City (e.g. San Francisco): ")
	locality, _ := reader.ReadString('\n')
	locality = strings.TrimSpace(locality)

	// Email
	fmt.Print("Email Address: ")
	emailAddress, _ := reader.ReadString('\n')
	emailAddress = strings.TrimSpace(emailAddress)

	// Key size
	fmt.Print("RSA Key Size (2048, 3072, or 4096) [default: 2048]: ")
	keySizeStr, _ := reader.ReadString('\n')
	keySizeStr = strings.TrimSpace(keySizeStr)
	keySize := 2048 // default value
	if keySizeStr != "" {
		fmt.Sscanf(keySizeStr, "%d", &keySize)
		// Validate key size
		validSizes := map[int]bool{2048: true, 3072: true, 4096: true}
		if !validSizes[keySize] {
			fmt.Println("Invalid key size. Using default: 2048")
			keySize = 2048
		}
	}

	// Output file prefix
	fmt.Print("Output file prefix [default: cert]: ")
	filePrefix, _ := reader.ReadString('\n')
	filePrefix = strings.TrimSpace(filePrefix)
	if filePrefix == "" {
		filePrefix = "cert"
	}
	
	// Get self-signed preference from command line or ask user
	createSelfsigned := *selfSignedFlag
	validDays := *daysFlag
	
	// If not specified via command line flag, ask the user
	if !*selfSignedFlag {
		fmt.Print("\nDo you want to create a self-signed certificate? [y/N]: ")
		selfSigned, _ := reader.ReadString('\n')
		selfSigned = strings.TrimSpace(strings.ToLower(selfSigned))
		createSelfsigned = selfSigned == "y" || selfSigned == "yes"
	}
	
	// Get certificate validity period if self-signed and not from command line
	if createSelfsigned && !*selfSignedFlag {
		fmt.Print("Certificate validity in days [default: 365]: ")
		validDaysStr, _ := reader.ReadString('\n')
		validDaysStr = strings.TrimSpace(validDaysStr)
		if validDaysStr != "" {
			fmt.Sscanf(validDaysStr, "%d", &validDays)
			if validDays <= 0 {
				fmt.Println("Invalid validity period. Using default: 365 days")
				validDays = 365
			}
		}
	}

	// Get domain name alternatives
	fmt.Println("\nDo you want to add Subject Alternative Names (SANs)? [y/N]: ")
	addSANs, _ := reader.ReadString('\n')
	addSANs = strings.TrimSpace(strings.ToLower(addSANs))
	
	var sans []string
	if addSANs == "y" || addSANs == "yes" {
		fmt.Println("Enter Subject Alternative Names (one per line, blank line to finish):")
		for {
			san, _ := reader.ReadString('\n')
			san = strings.TrimSpace(san)
			if san == "" {
				break
			}
			sans = append(sans, san)
		}
	}

	// Generate private key
	fmt.Printf("\nGenerating RSA private key (%d bits)...\n", keySize)
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		os.Exit(1)
	}

	// Create CSR template
	subj := pkix.Name{
		CommonName:         commonName,
		Organization:       []string{organization},
		OrganizationalUnit: []string{organizationalUnit},
		Country:            []string{country},
		Province:           []string{state},
		Locality:           []string{locality},
	}

	// Create CSR template with SAN if provided
	template := &x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Add SANs if provided
	if len(sans) > 0 {
		sanExtension := pkix.Extension{}
		sanExtension.Id = []int{2, 5, 29, 17} // SubjectAltName OID

		// Create a new extension value to hold all DNS names
		var rawValues []asn1.RawValue
		for _, san := range sans {
			rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(san)})
		}

		sequence, err := asn1.Marshal(rawValues)
		if err != nil {
			fmt.Printf("Error encoding SANs: %v\n", err)
			os.Exit(1)
		}

		sanExtension.Value = sequence
		template.ExtraExtensions = []pkix.Extension{sanExtension}
		fmt.Printf("Added %d Subject Alternative Names to the CSR\n", len(sans))
	}

	// Create CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		fmt.Printf("Error creating CSR: %v\n", err)
		os.Exit(1)
	}

	// Create output directory if specified and doesn't exist
	outputDir := *outputDirFlag
	if outputDir != "" {
		// Ensure the directory exists
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			fmt.Printf("Error creating output directory: %v\n", err)
			os.Exit(1)
		}
	}
	
	// Determine file paths based on output directory
	keyPath := filePrefix + ".key"
	csrPath := filePrefix + ".csr"
	crtPath := filePrefix + ".crt"
	
	if outputDir != "" {
		keyPath = filepath.Join(outputDir, keyPath)
		csrPath = filepath.Join(outputDir, csrPath)
		crtPath = filepath.Join(outputDir, crtPath)
	}
	
	// Save private key to file
	keyFile, err := os.Create(keyPath)
	if err != nil {
		fmt.Printf("Error creating key file: %v\n", err)
		os.Exit(1)
	}
	defer keyFile.Close()

	// Encode private key to PEM format
	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(keyFile, keyPEM); err != nil {
		fmt.Printf("Error encoding private key: %v\n", err)
		os.Exit(1)
	}

	// Save CSR to file
	csrFile, err := os.Create(csrPath)
	if err != nil {
		fmt.Printf("Error creating CSR file: %v\n", err)
		os.Exit(1)
	}
	defer csrFile.Close()

	// Encode CSR to PEM format
	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	if err := pem.Encode(csrFile, csrPEM); err != nil {
		fmt.Printf("Error encoding CSR: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nSuccess!")
	fmt.Printf("Private key saved to: %s\n", keyPath)
	fmt.Printf("CSR saved to: %s\n", csrPath)
	
	// Generate self-signed certificate if requested
	if createSelfsigned {
		// Create a self-signed certificate template
		notBefore := time.Now()
		notAfter := notBefore.Add(time.Duration(validDays) * 24 * time.Hour)
		
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			fmt.Printf("Failed to generate serial number: %v\n", err)
			os.Exit(1)
		}
		
		certTemplate := x509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               subj,
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		
		// Add DNS names if SANs were provided
		if len(sans) > 0 {
			certTemplate.DNSNames = sans
		}
		
		// If common name looks like a domain name, add it to DNS names as well
		if !contains(certTemplate.DNSNames, commonName) && strings.Contains(commonName, ".") {
			certTemplate.DNSNames = append(certTemplate.DNSNames, commonName)
		}
		
		// Create the certificate
		derBytes, err := x509.CreateCertificate(
			rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
		if err != nil {
			fmt.Printf("Failed to create certificate: %v\n", err)
			os.Exit(1)
		}
		
		// Save the certificate to file
		certFile, err := os.Create(crtPath)
		if err != nil {
			fmt.Printf("Failed to create certificate file: %v\n", err)
			os.Exit(1)
		}
		defer certFile.Close()
		
		// Encode certificate to PEM format
		certPEM := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		}
		if err := pem.Encode(certFile, certPEM); err != nil {
			fmt.Printf("Failed to encode certificate: %v\n", err)
			os.Exit(1)
		}
		
		fmt.Printf("Self-signed certificate saved to: %s\n", crtPath)
		fmt.Printf("Certificate is valid for %d days (until %s)\n", 
			validDays, notAfter.Format("2006-01-02"))
	} else {
		fmt.Println("\nYou can now submit the CSR file to your Certificate Authority.")
	}
	
	fmt.Println("Keep your private key file secure and do not share it with anyone.")
}
