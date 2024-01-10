package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

func main2() {
	// Replace this with your SSH public key string
	sshPublicKey := "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlWXFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww68/eIFmb1zuUFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8b+gw3r3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q== schacon@mylaptop.local"

	str, err := convertSSHPublicKeyToPEM(sshPublicKey)
	if err != nil {
		fmt.Println("Error to cnvert pems:", err)
		return
	}
	fmt.Println(str)

	// Parse the SSH public key
	rsaPublicKey, err := parseRSAPublicKeyFromPEM(str)
	if err != nil {
		fmt.Println("Error parsing SSH public key:", err)
		return
	}

	// Validate the RSA public key
	err = validateRSAPublicKey(rsaPublicKey)
	if err != nil {
		fmt.Println("RSA public key validation failed:", err)
		return
	}

	fmt.Println("RSA public key is valid!")
}

func parseRSAPublicKeyFromPEM(publicKeyPEM string) (*rsa.PublicKey, error) {
	// Decode the PEM-encoded public key
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("Failed to decode PEM block containing RSA public key")
	}

	// Parse the DER-encoded public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse RSA public key: %v", err)
	}

	// Assert the type to RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Not an RSA public key")
	}

	return rsaPubKey, nil
}

// parseSSHPublicKey parses an SSH public key string and returns an *rsa.PublicKey.
func parseSSHPublicKey1(sshPublicKey string) (*rsa.PublicKey, error) {
	// Extract the public key from the SSH key string
	block, _ := pem.Decode([]byte(sshPublicKey))
	fmt.Println("block---,", block)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("Failed to decode PEM block containing public key")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key: %v", err)
	}

	// Assert the type to RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Not an RSA public key")
	}

	return rsaPubKey, nil
}

// validateRSAPublicKey validates an RSA public key.
func validateRSAPublicKey(rsaPublicKey *rsa.PublicKey) error {
	// You can add custom validation logic here based on your requirements
	// For example, check key size, modulus, etc.
	// For simplicity, this example only checks if the key is not nil.

	if rsaPublicKey == nil {
		return fmt.Errorf("RSA public key is nil")
	}

	return nil
}

func convertSSHPublicKeyToPEM(sshPublicKey string) (string, error) {
	// Split the SSH public key string into its components
	parts := strings.Fields(sshPublicKey)
	if len(parts) < 2 || parts[0] != "ssh-rsa" {
		return "", fmt.Errorf("Invalid SSH public key format")
	}

	// Decode the base64-encoded part of the key
	decodedKey, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("Failed to decode base64: %v", err)
	}

	// Create a PEM block
	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: decodedKey,
	}

	// Encode the PEM block to a string
	pemString := string(pem.EncodeToMemory(pemBlock))

	return pemString, nil
}
