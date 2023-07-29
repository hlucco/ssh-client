package shared

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"net"

	"golang.org/x/crypto/hkdf"
)

func GenerateKeys(sharedSecret []byte) ([]byte, []byte) {
	masterKey := make([]byte, 64)
	hash := sha256.Sum256([]byte("sshsalt"))
	hkdfSalt := hash[:32]
	hkdf := hkdf.New(sha256.New, sharedSecret, hkdfSalt, nil)
	if _, err := hkdf.Read(masterKey); err != nil {
		fmt.Println("Error generating master key:", err)
		return nil, nil
	}

	// Split the master key into a 32-byte AES key and a 32-byte HMAC key.
	aesKey := masterKey[:32]
	hmacKey := masterKey[32:]

	return aesKey, hmacKey
}

func pad(plaintext []byte, blockSize int) []byte {
	padding := blockSize - (len(plaintext) % blockSize)
	paddedBytes := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, paddedBytes...)
}

// Format: IV (16 bytes) | Ciphertext | HMAC (32 bytes)
func EncryptAndSend(aesKey []byte, hmacKey []byte, packet Packet, conn net.Conn) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(packet)
	if err != nil {
		fmt.Println("Error encoding DHINIT struct:", err)
		return
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		fmt.Println("Error creating AES cipher:", err)
		return
	}

	// encrypt and mac because SSH

	iv := make([]byte, 16)
	rand.Read(iv)

	paddedPacket := pad(buf.Bytes(), block.BlockSize())
	cbc := cipher.NewCBCEncrypter(block, iv)

	// fmt.Println("Plaintext:", paddedPacket)

	ciphertext := make([]byte, len(paddedPacket))
	cbc.CryptBlocks(ciphertext, paddedPacket)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(paddedPacket)
	macBytes := mac.Sum(nil)

	message := append(iv, ciphertext...)
	message = append(message, macBytes...)

	// fmt.Println("Sending message:", message)

	_, err = conn.Write(message)
	if err != nil {

		fmt.Println("Error sending dhinit packet:", err)
		return
	}
}

// Format: IV (16 bytes) | Ciphertext | HMAC (32 bytes)
func DecryptAndVerify(aesKey []byte, hmacKey []byte, packet interface{}, conn net.Conn) {

	message := make([]byte, 1024)
	n, err := conn.Read(message)
	if err != nil {
		fmt.Println("Error receiving data from server:", err)
		return
	}
	message = message[:n]

	// fmt.Println("Recieved message:", message)

	iv := message[:16]
	ciphertext := message[16 : len(message)-32]
	mac := message[len(message)-32:]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		fmt.Println("Error creating AES cipher:", err)
		return
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cbc.CryptBlocks(plaintext, ciphertext)

	// fmt.Println("Plaintext:", plaintext)

	// Verify HMAC
	mac2 := hmac.New(sha256.New, hmacKey)
	mac2.Write(plaintext)
	macBytes := mac2.Sum(nil)

	if !hmac.Equal(mac, macBytes) {
		fmt.Println("HMACs don't match!")
		return
	}

	decoder := gob.NewDecoder(bytes.NewReader(plaintext))
	err = decoder.Decode(packet)
	if err != nil {
		fmt.Println("Error decoding struct:", err)
		return
	}
}
