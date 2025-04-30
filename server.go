package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	log.SetFlags(0)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "crypto.html")
	}))
	http.Handle("POST /encrypt", http.HandlerFunc(encrypt))
	// http.Handle("/decrypt", http.HandlerFunc(decrypt))
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

type Result struct {
	Text string `json:"text"`
}

type CryptoRequest struct {
	Text         string `json:"text"`
	Key          string `json:"key"`
	KeySize      int    `json:"key_size"`
	Mode         string `json:"mode"`
	OutputFormat string `json:"format"`
}

func encrypt(w http.ResponseWriter, r *http.Request) {
	// size := r.FormValue("key_size")
	// mode := r.FormValue("mode")
	// format := r.FormValue("format")

	var req CryptoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// TODO: return http.StatusBadRequest error
	}

	key, _ := hex.DecodeString(req.Key)
	plaintext := []byte(req.Text)

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, _ := aes.NewCipher(key)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Printf("%v\n", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// data := &Cipher{
	// 	Key:    hex.EncodeToString(key),
	// 	Text:   string(plaintext),
	// 	Result: hex.EncodeToString(ciphertext),
	// }
	// runTemplate(w, data)
	result := Result{Text: hex.EncodeToString(ciphertext)}
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(&result)
	fmt.Fprint(w, string(data))
}

// func decrypt(w http.ResponseWriter, r *http.Request) {
// 	key, _ := hex.DecodeString(r.FormValue("key"))
// 	text := r.FormValue("text")
// 	ciphertext, _ := hex.DecodeString(text)

// 	block, _ := aes.NewCipher(key)

// 	// The IV needs to be unique, but not secure. Therefore it's common to
// 	// include it at the beginning of the ciphertext.
// 	if len(ciphertext) < aes.BlockSize {
// 		log.Println("ciphertext too short")
// 	}

// 	iv := ciphertext[:aes.BlockSize]
// 	ciphertext = ciphertext[aes.BlockSize:]

// 	// CBC mode always works in whole blocks.
// 	if len(ciphertext)%aes.BlockSize != 0 {
// 		log.Println("ciphertext is not a multiple of the block size")
// 	}

// 	mode := cipher.NewCBCDecrypter(block, iv)

// 	// CryptBlocks can work in-place if the two arguments are the same.
// 	mode.CryptBlocks(ciphertext, ciphertext)

// 	// If the original plaintext lengths are not a multiple of the block
// 	// size, padding would have to be added when encrypting, which would be
// 	// removed at this point. For an example, see
// 	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
// 	// critical to note that ciphertexts must be authenticated (i.e. by
// 	// using crypto/hmac) before being decrypted in order to avoid creating
// 	// a padding oracle.

// 	data := &Cipher{
// 		Key:    hex.EncodeToString(key),
// 		Text:   text,
// 		Result: string(ciphertext),
// 	}
// 	runTemplate(w, data)
// }

// func runTemplate(w http.ResponseWriter, data interface{}) {
// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	if err := templ.Execute(w, data); err != nil {
// 		log.Printf("templ.Execute(w, %+v): %v", data, err)
// 	}
// }
