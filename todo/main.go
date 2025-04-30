package main

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"repo.redlink.com.ar/transaccional/psi/prsi/enc/cipher"
)

// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation:
//
// A block cipher works on units of a fixed size (known as a block size),
// but messages come in a variety of lengths. So some modes (namely ECB and CBC)
// require that the final block be padded before encryption. Several padding
// schemes exist. The simplest is to add null bytes to the plaintext to bring
// its length up to a multiple of the block size.

// func encrypt(key, plaintext []byte) {
// }

// decrypt decrypts src into dst using key.
// Dst and src may overlap entirely or not at all.
func decrypt(key []byte, dst, src []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// ECB mode always works in whole blocks.
	if len(src)%aes.BlockSize != 0 {
		panic("src is not a multiple of the block size")
	}

	mode := cipher.NewECBDecrypter(block)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(dst, src)

	// Remove null bytes from the plaintext.
	dst, _, _ = bytes.Cut(dst, []byte{0})
}

func main() {
	key, _ := hex.DecodeString("6B5AB8BAD7AB24EF6ABF67058534ACBD")
	// ciphertext, _ := hex.DecodeString("9CBF0DAE8C6710BB7FD792104BEF1E55")

	ciphertext, _ := io.ReadAll(os.Stdin)
	ciphertext, _ = hex.DecodeString(string(ciphertext))

	decrypt(key, ciphertext, ciphertext)

	fmt.Printf("%s\n", ciphertext)
}
