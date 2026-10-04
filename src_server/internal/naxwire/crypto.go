package naxwire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const aesBlock = 16

// EncryptCBC takes a 16-byte key, a 16-byte IV, and a plaintext, PKCS#7-pads
// the plaintext, AES-128-CBC encrypts, and returns IV || ciphertext.
func EncryptCBC(key, iv, plaintext []byte) ([]byte, error) {
	if len(key) != aesBlock {
		return nil, errors.New("nax-crypto: key must be 16 bytes")
	}
	if len(iv) != aesBlock {
		return nil, errors.New("nax-crypto: IV must be 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aesBlock)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	out := make([]byte, aesBlock+len(ct))
	copy(out, iv)
	copy(out[aesBlock:], ct)
	return out, nil
}

// EncryptCBCRandomIV is the production helper - generates a fresh random IV.
func EncryptCBCRandomIV(key, plaintext []byte) ([]byte, error) {
	iv := make([]byte, aesBlock)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return EncryptCBC(key, iv, plaintext)
}

// DecryptCBC takes a 16-byte key and an envelope of the form IV || ciphertext,
// AES-128-CBC decrypts, validates and strips PKCS#7 padding, returns plaintext.
func DecryptCBC(key, envelope []byte) ([]byte, error) {
	if len(key) != aesBlock {
		return nil, errors.New("nax-crypto: key must be 16 bytes")
	}
	if len(envelope) < aesBlock+aesBlock {
		return nil, errors.New("nax-crypto: envelope too short")
	}
	if (len(envelope)-aesBlock)%aesBlock != 0 {
		return nil, errors.New("nax-crypto: ciphertext length not a multiple of block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := envelope[:aesBlock]
	ct := envelope[aesBlock:]
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	return pkcs7Unpad(pt)
}

func pkcs7Pad(p []byte, block int) []byte {
	pad := block - (len(p) % block)
	out := make([]byte, len(p)+pad)
	copy(out, p)
	for i := len(p); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(p []byte) ([]byte, error) {
	if len(p) == 0 {
		return nil, errors.New("nax-crypto: empty padded plaintext")
	}
	pad := int(p[len(p)-1])
	if pad < 1 || pad > aesBlock || pad > len(p) {
		return nil, errors.New("nax-crypto: invalid PKCS#7 padding byte")
	}
	for i := len(p) - pad; i < len(p); i++ {
		if p[i] != byte(pad) {
			return nil, errors.New("nax-crypto: corrupted PKCS#7 padding")
		}
	}
	return p[:len(p)-pad], nil
}
