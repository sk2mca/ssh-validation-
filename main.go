package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

func main() {
	// Replace this with your SSH public key string
	sshPublicKey := "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlWXFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww68/eIFmb1zuUFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8b+gw3r3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q== schacon@mylaptop.local"

	// Convert SSH public key to RSA public key
	err := parseSSHPublicKey(sshPublicKey)
	if err != nil {
		fmt.Println("Error parsing SSH public key:", err)
		return
	}

	fmt.Println("Successfully parsed RSA public key:")
	//fmt.Println(rsaPublicKey)
}

// parseSSHPublicKey parses an SSH public key string and returns an *rsa.PublicKey.

func parseSSHPublicKey(sshPublicKey string) error {
	// Split the SSH public key string into its components
	parts := strings.Fields(sshPublicKey)
	if len(parts) < 2 || parts[0] != "ssh-rsa" {
		return fmt.Errorf("Invalid SSH public key format")
	}

	// Decode the base64-encoded part of the key
	decodedKey, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("Failed to decode base64: %v", err)
	}

	// Parse the SSH public key
	parsedKey, err := ssh.ParsePublicKey(decodedKey)
	if err != nil {
		return fmt.Errorf("Failed to parse SSH public key: %v", err)
	}

	// Assert the type to RSA public key
	rsaPubKey, ok := parsedKey.(ssh.PublicKey)
	if !ok {
		return fmt.Errorf("Not an RSA public key")
	}
	fmt.Println("rsaPubKey:", rsaPubKey)
	return nil
}
