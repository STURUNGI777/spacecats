package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Get the encryption key
func getKey() ([]byte, error) {
	key := os.Getenv("AES_KEY") // Read from an environment variable
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: AES-256 requires a 32-byte key")
	}
	return []byte(key), nil
}

// Encrypt a single file and delete the original
func encryptFile(filename string, key []byte) error {
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("error generating nonce: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	encryptedFilename := filename + ".enc"
	err = os.WriteFile(encryptedFilename, ciphertext, 0644)
	if err != nil {
		return fmt.Errorf("error writing encrypted file: %w", err)
	}

	// Delete the original file after encryption
	err = os.Remove(filename)
	if err != nil {
		return fmt.Errorf("error deleting original file: %w", err)
	}

	fmt.Println("Encrypted and removed:", filename)
	return nil
}

// Encrypt all files in a given folder
func encryptFolder(folderPath string, key []byte) error {
	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		fmt.Println("Encrypting:", path)
		return encryptFile(path, key)
	})

	return err
}

func main() {
	// Check if folder path is provided
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run encryptor.go <folder_path>")
		return
	}

	folderPath := os.Args[1] // Get folder path from command-line argument

	key, err := getKey()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = encryptFolder(folderPath, key)
	if err != nil {
		fmt.Println("Encryption Error:", err)
		return
	}

	fmt.Println("All files in", folderPath, "encrypted successfully!")
}
