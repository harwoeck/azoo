package dvx

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"azoo.dev/utils/dvx/totp"
)

const (
	// Version is the version header of the current Protocol implementation. It
	// is the lower-cased string name of the underlying Primitive.
	Version string = "dv1"
)

// Protocol is an implementation of the current major dvx version. It can
// decrypt and verify ciphers, signatures and tags from all previous major
// versions.
//
// This means the Protocol implementation under azoo.dev/utils/dvx will always
// use DV1 as it's Primitive. When DV2 will eventually get released, it will be
// hosted under azoo.dev/utils/dvx/v2, and it's Protocol will use DV2 as it's
// Primitive, but will be able to decrypt and verify DV1 content.
//
// The interface of Protocol is closely tied to that of Dragon (originally it's
// parent project), but may be used directly in non-Dragon scenarios or to
// locally verify signatures (VerifyPK) without the need to contact a Dragon
// server.
type Protocol struct {
	keys map[string]KeyPool
}

// NewProtocol creates a new Protocol from a map of KeyPool. The map specifies
// different KeyPool for major DVX versions.
//
// Therefore, a valid map would be:
//   map[string]dvx.KeyPool{
//     dvx.Version: dvx.WrapDVXAsKeyPool(dvx.DV1{}, []byte{}),
//   }
func NewProtocol(keyPools map[string]KeyPool) *Protocol {
	return &Protocol{
		keys: keyPools,
	}
}

func (p *Protocol) keyRingToBytes(keyRing string) []byte {
	idx := strings.IndexRune(keyRing, ':')
	if idx == -1 {
		return []byte(keyRing)
	}

	base64Buf, err := base64.RawStdEncoding.DecodeString(keyRing[idx+1:])
	if err != nil {
		// if base64 decode fails we use the bytes' representation of the string
		// itself
		return []byte(keyRing)
	}

	// in cases where decode succeeds we use the decoded base64 buffer
	return base64Buf
}

// Encrypt derives a secret key `sk` using the keyRing and subsequently
// encrypts data using `sk`.
func (p *Protocol) Encrypt(keyRing string, data []byte) (ciphertext string, err error) {
	key, err := p.keys[Version].KDF32(p.keyRingToBytes(keyRing))
	if err != nil {
		return "", err
	}

	cipher, err := DV1{}.Encrypt(key, data)
	if err != nil {
		return "", err
	}

	return Encode(Encrypted, cipher), nil
}

func (p *Protocol) decrypt(keyRing []byte, cipher []byte, version string) (data []byte, err error) {
	switch version {
	case "dv1":
		key, err := p.keys[version].KDF32(keyRing)
		if err != nil {
			return nil, err
		}

		data, err = DV1{}.Decrypt(key, cipher)
		if err != nil {
			return nil, err
		}
	}
	return
}

// Decrypt derives a secret key `sk` using the keyRing and subsequently
// decrypts ciphertext using `sk`.
func (p *Protocol) Decrypt(keyRing string, ciphertext string) (data []byte, err error) {
	v, d, err := DecodeExpect(ciphertext, Encrypted)
	if err != nil {
		return nil, err
	}

	return p.decrypt(p.keyRingToBytes(keyRing), d, v)
}

func (p *Protocol) deriveSignKey(keyRing []byte, version string) (privateKey []byte, err error) {
	switch version {
	case "dv1":
		seed, err := p.keys[Version].KDF32(keyRing)
		if err != nil {
			return nil, err
		}

		privateKey = ed25519.NewKeyFromSeed(seed)
	}
	return
}

// CreateSignKey derives a private key using the keyRing and returns its
// public key counterpart to the caller. It can be used in conjunction
// with VerifyPK to verify signatures created with Sign using the same
// keyRing.
func (p *Protocol) CreateSignKey(keyRing string) (publicKey []byte, err error) {
	privateKey, err := p.deriveSignKey(p.keyRingToBytes(keyRing), Version)
	if err != nil {
		return nil, err
	}

	return ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey), nil
}

// Sign derives a private key using the keyRing and subsequently calculates
// a signature for data.
func (p *Protocol) Sign(keyRing string, message []byte) (signature string, rawSignature []byte, err error) {
	key, err := p.deriveSignKey(p.keyRingToBytes(keyRing), Version)
	if err != nil {
		return "", nil, err
	}

	sig, err := DV1{}.Sign(key, message)
	if err != nil {
		return "", nil, err
	}

	return Encode(Signed, sig), sig, nil
}

func (p *Protocol) verifyPK(publicKey []byte, message []byte, signature []byte, version string) (valid bool, err error) {
	switch version {
	case "dv1":
		valid, err = DV1{}.Verify(publicKey, message, signature)
		if err != nil {
			return false, err
		}
	}
	return
}

func (p *Protocol) verify(keyRing []byte, message []byte, signature []byte, version string) (valid bool, err error) {
	var publicKey []byte

	switch version {
	case "dv1":
		privateKey, err := p.deriveSignKey(keyRing, "dv1")
		if err != nil {
			return false, err
		}
		publicKey = ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	}

	return p.verifyPK(publicKey, message, signature, version)
}

// Verify derives a private key using the keyRing and subsequently uses its
// public key counterpart to verify the signature for data.
func (p *Protocol) Verify(keyRing string, message []byte, signature string) (valid bool, err error) {
	v, sig, err := DecodeExpect(signature, Signed)
	if err != nil {
		return false, err
	}

	return p.verify(p.keyRingToBytes(keyRing), message, sig, v)
}

// VerifyPK uses the provided public key directly to verify the signature for
// data. VerifyPK doesn't derive any key from the internal KeyPool and is safe
// to use for Protocol objects with empty KeyPool maps. It can be used verify a
// DVX signature string without access to the KeyPool and respectively private
// key counterparts.
func (p *Protocol) VerifyPK(publicKey []byte, message []byte, signature string) (valid bool, err error) {
	v, signatureBuf, err := DecodeExpect(signature, Signed)
	if err != nil {
		return false, err
	}

	return p.verifyPK(publicKey, message, signatureBuf, v)
}

// MAC derives a secret key `sk` using the keyRing and subsequently calculates
// a MAC tag of data using `sk`.
func (p *Protocol) MAC(keyRing string, message []byte) (tag string, err error) {
	key, err := p.keys[Version].KDF64(p.keyRingToBytes(keyRing))
	if err != nil {
		return "", err
	}

	buffer, err := DV1{}.MAC512(key, message)
	if err != nil {
		return "", err
	}

	return Encode(Tagged, buffer), nil
}

func (p *Protocol) deriveTOTPKey(keyRing []byte, rawID []byte, accountID string, version string) (key []byte, err error) {
	switch version {
	case "dv1":
		totpSK, err := p.keys[Version].KDF64(keyRing)
		if err != nil {
			return nil, err
		}

		intermediate, err := DV1{}.MAC512(totpSK, rawID)
		if err != nil {
			return nil, err
		}

		key, err = DV1{}.MAC256(intermediate, []byte(accountID))
		if err != nil {
			return nil, err
		}
	}
	return
}

// GenerateTOTP derives a secret key `sk` using the keyRing. Afterwards, it
// generates 32 random bytes `raw-id`, which are encoded to a totp-id using
// Encode with a TOTP TypePrefix. Subsequently, `sk` and `raw-id` are used to
// derive an intermediate key `i`, which is mixed with an `accountID` to
// cryptographically bind the final totp-secret-key `totp-sk` to a specific
// end-user account.
//
// The `totp-sk` secret used for totp calculations has 32 bytes and SHA256 is
// selected as a totp algorithm. Moreover, digits and period are left to their
// defaults: 6 and 30 respectively.
//
// The returned `id` must be stored by the caller in order to VerifyTOTP codes
// in the future. NO additional integrity checks/measurements are needed in
// storage to protect from id-swapping attacks, as `account-id` is
// cryptographically bound and `totp-sk` depends on it. Although the returned
// `id` is useless in itself, it should not be returned to the end-user client.
//
// The returned uri is a Google Authenticator compliant URI
// string (https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
// that can be used by end-users to set up an authenticator. It can be
// directly passed to azoo.dev/utils/qr generator to create a QR-image of the
// uri for easy end-user set up.
func (p *Protocol) GenerateTOTP(keyRing string, issuer string, accountName string, accountID string) (id string, uri string, err error) {
	rawID := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, rawID)
	if err != nil {
		return "", "", fmt.Errorf("dvx: cannot generate totp id: %v", err)
	}
	id = Encode(TOTP, rawID)

	key, err := p.deriveTOTPKey(p.keyRingToBytes(keyRing), rawID, accountID, Version)
	if err != nil {
		return "", "", err
	}

	uri = (&totp.TOTP{
		Secret:      key,
		Algorithm:   "SHA256",
		Digits:      6,
		Period:      30,
		Issuer:      issuer,
		AccountName: accountName,
	}).URI()

	return
}

// VerifyTOTP derives a totp-secret-key `totp-sk` using the same procedure as
// described in GenerateTOTP and subsequently uses it to verify the provided
// code in constant-time.
func (p *Protocol) VerifyTOTP(keyRing string, id string, accountID string, code string) (valid bool, err error) {
	v, rawID, err := DecodeExpect(id, TOTP)
	if err != nil {
		return false, err
	}

	key, err := p.deriveTOTPKey(p.keyRingToBytes(keyRing), rawID, accountID, v)
	if err != nil {
		return false, err
	}

	switch v {
	case "dv1":
		valid, err = (&totp.TOTP{
			Secret:    key,
			Algorithm: "SHA256",
			Digits:    6,
			Period:    30,
		}).Verify(code)
	}
	return
}
