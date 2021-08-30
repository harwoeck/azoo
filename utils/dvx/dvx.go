package dvx

// Primitive is a low level cryptographic contract.
type Primitive interface {
	KDF512(password []byte, salt []byte) (key []byte, err error)
	MAC256(key []byte, message []byte) (tag []byte, err error)
	MAC512(key []byte, message []byte) (tag []byte, err error)
	Encrypt(key []byte, data []byte) (cipher []byte, err error)
	Decrypt(key []byte, cipher []byte) (data []byte, err error)
	Sign(privateKey []byte, message []byte) (signature []byte, err error)
	Verify(publicKey []byte, message []byte, signature []byte) (valid bool, err error)
}
