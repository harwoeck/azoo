package dvx

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDV1_EncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	myData := []byte("some random data")

	cipher, err := DV1{}.Encrypt(key, myData)
	require.NoError(t, err)
	assert.NotEqual(t, myData, cipher)

	plain, err := DV1{}.Decrypt(key, cipher)
	require.NoError(t, err)
	assert.Equal(t, myData, plain)
}

func TestDV1_MAC256(t *testing.T) {
	key := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	data := []byte("message")

	tag1, err := DV1{}.MAC256(key, data)
	require.NoError(t, err)
	assert.NotEqual(t, tag1, data)

	tag2, err := DV1{}.MAC256(key, data)
	require.NoError(t, err)
	assert.NotEqual(t, tag2, data)

	assert.Equal(t, tag1, tag2)
}

func TestDV1_MAC512(t *testing.T) {
	key := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	data := []byte("message")

	tag1, err := DV1{}.MAC512(key, data)
	require.NoError(t, err)
	assert.NotEqual(t, tag1, data)

	tag2, err := DV1{}.MAC512(key, data)
	require.NoError(t, err)
	assert.NotEqual(t, tag2, data)

	assert.Equal(t, tag1, tag2)
}

func TestDV1_SignVerify(t *testing.T) {
	key := make([]byte, ed25519.SeedSize)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	privateKey := ed25519.NewKeyFromSeed(key)

	signature, err := DV1{}.Sign(privateKey, []byte("message"))
	require.NoError(t, err)

	valid, err := DV1{}.Verify(privateKey.Public().(ed25519.PublicKey), []byte("message"), signature)
	require.NoError(t, err)
	assert.True(t, valid)

	signature[0], signature[1] = signature[1], signature[0]
	signature[10], signature[11] = signature[11], signature[10]
	signature[20], signature[21] = signature[21], signature[20]
	signature[30], signature[31] = signature[31], signature[30]
	signature[40], signature[41] = signature[41], signature[40]
	signature[50], signature[51] = signature[51], signature[50]
	signature[60], signature[61] = signature[61], signature[60]
	valid, err = DV1{}.Verify(privateKey.Public().(ed25519.PublicKey), []byte("message"), signature)
	require.NoError(t, err)
	assert.False(t, valid)
}
