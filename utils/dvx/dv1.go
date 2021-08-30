package dvx

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

type DV1 struct {
}

func (d DV1) KDF512(password []byte, salt []byte) (key []byte, err error) {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 64), nil
}

func (d DV1) MAC256(key []byte, message []byte) (tag []byte, err error) {
	if len(key) != blake2b.Size {
		return nil, fmt.Errorf("dv1: mac key must be %d bytes long", blake2b.Size)
	}
	h, _ := blake2b.New256(key) // err is always nil
	h.Write(message)
	return h.Sum(nil), nil
}

func (d DV1) MAC512(key []byte, message []byte) (tag []byte, err error) {
	if len(key) != blake2b.Size {
		return nil, fmt.Errorf("dv1: mac key must be %d bytes long", blake2b.Size)
	}
	h, _ := blake2b.New512(key) // err is always nil
	h.Write(message)
	return h.Sum(nil), nil
}

func (d DV1) Encrypt(key []byte, data []byte) (cipher []byte, err error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("dv1: key must be %d bytes long", chacha20poly1305.KeySize)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("dv1: failed to read random %d bytes for nonceKey: %v", chacha20poly1305.NonceSizeX, err)
	}

	aead, _ := chacha20poly1305.NewX(key) // err is always nil
	encrypted := aead.Seal(data[:0], nonce, data, append([]byte(Version), nonce...))
	return append(nonce, encrypted...), nil
}

func (d DV1) Decrypt(key []byte, cipher []byte) (data []byte, err error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("dv1: key must be %d bytse long", chacha20poly1305.KeySize)
	}
	if len(cipher) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("dv1: cipher shorter (%d) than needed for nonce (%d)", len(cipher), chacha20poly1305.NonceSizeX)
	}

	nonce := cipher[:chacha20poly1305.NonceSizeX]
	encrypted := cipher[chacha20poly1305.NonceSizeX:]

	aead, _ := chacha20poly1305.NewX(key) // err is always nil
	data, err = aead.Open(nil, nonce, encrypted, append([]byte(Version), nonce...))
	if err != nil {
		return nil, fmt.Errorf("dv1: open failed: %v", err)
	}

	return
}

func (d DV1) Sign(privateKey []byte, message []byte) (signature []byte, err error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("dv1: private key must be %d bytes long", ed25519.PrivateKeySize)
	}
	return ed25519.Sign(privateKey, message), nil
}

func (d DV1) Verify(publicKey []byte, message []byte, signature []byte) (valid bool, err error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("dv1: public key must be %d bytes long", ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("dv1: signature must be %d bytes long", ed25519.SignatureSize)
	}
	return ed25519.Verify(publicKey, message, signature), nil
}
