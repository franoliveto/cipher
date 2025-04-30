package cipher

import (
	"crypto/cipher"
)

// Cipher electronic codebook (ECB) mode.

// The message is divided into blocks, and each block is encrypted or decrypted
// separately.

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
		// iv:        bytes.Clone(iv),
		// tmp:       make([]byte, b.BlockSize()),
	}
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	// if alias.InexactOverlap(dst[:len(src)], src) {
	// 	panic("crypto/cipher: invalid buffer overlap")
	// }

	// iv := x.iv

	// for len(src) > 0 {
	// 	// Write the xor to dst, then encrypt in place.
	// 	subtle.XORBytes(dst[:x.blockSize], src[:x.blockSize], iv)
	// 	x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])

	// 	// Move to the next block with this block as the next iv.
	// 	iv = dst[:x.blockSize]
	// 	src = src[x.blockSize:]
	// 	dst = dst[x.blockSize:]
	// }

}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic codebook
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	// if alias.InexactOverlap(dst[:len(src)], src) {
	// 	panic("crypto/cipher: invalid buffer overlap")
	// }
	if len(src) == 0 {
		return
	}

	end := len(src)
	start := end - x.blockSize
	for end > 0 {
		x.b.Decrypt(dst[start:end], src[start:end])

		end = start
		start = end - x.blockSize
	}
}
