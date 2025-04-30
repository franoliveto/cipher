package aes

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
)

// InvalidKeySizeError values describe errors resulting from an invalid key size.
type InvalidKeySizeError int

func (e InvalidKeySizeError) Error() string {
	return fmt.Sprintf("key needs to be %d bytes long", e)
}

// InvalidTextSizeError values describe errors resulting from invalid text size.
type InvalidTextSizeError int

func (e InvalidTextSizeError) Error() string {
	return fmt.Sprintf("text needs to be multiple of %d", e)
}

const AES128KeySize = 16

// Decrypt decrypts an hexadecimal encoded text using AES-128 with a 16 bytes long key,
// ECB as its mode, trailing zeroes unpadding.
func Decrypt(keyhex string, texthex string) (string, error) {

	key, err := hex.DecodeString(keyhex)
	if err != nil {
		return "", err
	}
	if len(key) != AES128KeySize {
		return "", InvalidKeySizeError(AES128KeySize)
	}

	ciphertext, err := hex.DecodeString(texthex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	bs := block.BlockSize()
	// ECB mode always works in whole blocks.
	if len(ciphertext)%bs != 0 {
		return "", InvalidTextSizeError(bs)
	}

	plaintext := make([]byte, len(ciphertext))
	dst := plaintext
	for len(ciphertext) > 0 {
		block.Decrypt(dst, ciphertext)
		dst = dst[bs:]
		ciphertext = ciphertext[bs:]
	}

	plaintext, err = ZeroUnpadding(plaintext, bs)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func ZeroUnpadding(text []byte, blockSize int) ([]byte, error) {
	if len(text)%blockSize != 0 || len(text) == 0 {
		return nil, InvalidTextSizeError(blockSize)
	}

	unpadded, _, _ := bytes.Cut(text, []byte{0})
	return unpadded, nil
}
