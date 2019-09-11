package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AES-GCM should be used because the operation is an authenticated encryption
// algorithm designed to provide both data authenticity (integrity) as well as
// confidentiality.

// Merged into Golang in https://go-review.googlesource.com/#/c/18803/

// AESGCMEncrypt takes an encryption key and a plaintext string and encrypts it with AES256 in GCM mode, which provides authenticated encryption. Returns the ciphertext and the used nonce.
func AESGCMEncrypt(rawBytes, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cipherBytes := aesgcm.Seal(nil, nonce, rawBytes, nil)
	// fmt.Printf("Nonce: %x\n", nonce)
	dataBytes := make([]byte, 12+len(cipherBytes))
	copy(dataBytes, nonce)
	copy(dataBytes[12:], cipherBytes)
	return dataBytes, nil
}

// AESGCMDecrypt takes an decryption key, a ciphertext and the corresponding nonce and decrypts it with AES256 in GCM mode. Returns the plaintext string.
func AESGCMDecrypt(cipherBytes, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := cipherBytes[:12]
	rawBytes, err := aesgcm.Open(nil, nonce, cipherBytes[12:], nil)
	if err != nil {
		return nil, err
	}
	return rawBytes, nil
}

// GenKey
func GenKey(len int) []byte {
	key := make([]byte, len)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	return key
}

// Test
func Test() error {
	// Generate an encryption key. 16 bytes = AES-128, 32 bytes = AES-256.
	key := GenKey(32)

	// Specify the plaintext input
	plaintext := "Lorem Ipsum"
	cipherBytes, err := AESGCMEncrypt([]byte(plaintext), key)
	if err != nil {
		return err
	}
	fmt.Printf("Ciphertext: %x\n", cipherBytes)
	// For decryption you need to provide the nonce which was used for the encryption
	plainBytes, err := AESGCMDecrypt(cipherBytes, key)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", string(plainBytes))
	return nil
}
