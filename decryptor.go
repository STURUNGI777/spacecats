package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"path/filepath"
)

// Get the encryption key from the environment variable
func getKey() ([]byte, error) {
	key := os.Getenv("AES_KEY")
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: AES-256 requires a 32-byte key")
	}
	return []byte(key), nil
}

// Decrypt a single file
func decryptFile(filename string, key []byte) error {
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading encrypted file: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("invalid ciphertext size")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Get original filename (remove .enc extension)
	originalFilename := filename[:len(filename)-4]

	// Write decrypted file
	err = os.WriteFile(originalFilename, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("error writing decrypted file: %w", err)
	}

	// Delete the encrypted file
	err = os.Remove(filename)
	if err != nil {
		return fmt.Errorf("error deleting encrypted file: %w", err)
	}

	fmt.Println("Decrypted:", originalFilename)
	return nil
}

// Decrypt all .enc files inside a folder
func decryptFolder(folderPath string, key []byte) error {
	return filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only process files with ".enc" extension
		if !info.IsDir() && filepath.Ext(path) == ".enc" {
			return decryptFile(path, key)
		}
		return nil
	})
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run decryptor.go <folder_path>")
		return
	}

	folderPath := os.Args[1]
	key, err := getKey()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = decryptFolder(folderPath, key)
	if err != nil {
		fmt.Println("Decryption Error:", err)
	} else {
		fmt.Println("Decryption Completed Successfully!")
	}
}
