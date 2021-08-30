package dvx

import (
	"crypto/rand"
	"io"
	"testing"

	logger "github.com/harwoeck/liblog/contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"azoo.dev/utils/dvx/totp"
)

func newProtocol(t *testing.T) *Protocol {
	rootKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, rootKey)
	require.Nil(t, err)

	p := NewProtocol(map[string]KeyPool{Version: WrapDVXAsKeyPool(DV1{}, rootKey, logger.MustNewStd())})
	require.NotNil(t, p)

	return p
}

func TestProtocol_Encrypt_KeyRingCheck(t *testing.T) {
	p := newProtocol(t)

	cipherA, err := p.Encrypt("keyring_a", []byte("data"))
	require.NoError(t, err)

	cipherB, err := p.Encrypt("keyring_b", []byte("data"))
	require.NoError(t, err)

	assert.NotEqual(t, cipherA, cipherB)

	_, err = p.Decrypt("keyring_a", cipherB)
	assert.Error(t, err)

	_, err = p.Decrypt("keyring_b", cipherA)
	assert.Error(t, err)
}

func TestProtocol_Encrypt_DataCheck(t *testing.T) {
	p := newProtocol(t)

	cipherA, err := p.Encrypt("keyring", []byte("data_a"))
	require.NoError(t, err)

	cipherB, err := p.Encrypt("keyring", []byte("data_b"))
	require.NoError(t, err)

	assert.NotEqual(t, cipherA, cipherB)

	dataA, err := p.Decrypt("keyring", cipherA)
	require.NoError(t, err)
	assert.Equal(t, []byte("data_a"), dataA)

	dataB, err := p.Decrypt("keyring", cipherB)
	require.NoError(t, err)
	assert.Equal(t, []byte("data_b"), dataB)
}

func TestProtocol_UseB64KeyRing(t *testing.T) {
	p := newProtocol(t)

	ciphertext, err := p.Encrypt("totp:dG90cA", []byte("data"))
	require.NoError(t, err)
	assert.NotEqual(t, ciphertext, "data")

	data, err := p.Decrypt("differentLabelButSameKeyRing:dG90cA", ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "data", string(data))

	data, err = p.Decrypt("totp:b3RoZXJLZXlSaW5n", ciphertext)
	assert.Error(t, err)
	assert.NotEqual(t, "data", string(data))
}

func TestProtocol_TOTP(t *testing.T) {
	p := newProtocol(t)

	totpID, uri, err := p.GenerateTOTP("totp", "i", "a1", "a1-id")
	require.NoError(t, err)

	client, err := totp.ParseFromURI(uri)
	require.NoError(t, err)
	require.NotNil(t, client)

	validCode, err := client.Generate()
	require.NoError(t, err)

	valid, err := p.VerifyTOTP("totp", totpID, "a1-id", validCode)
	require.NoError(t, err)
	assert.True(t, valid)

	notValid, err := p.VerifyTOTP("different-keyRing", totpID, "a1-id", validCode)
	require.NoError(t, err)
	assert.False(t, notValid)

	notValid, err = p.VerifyTOTP("totp", totpID, "spoofed-swapped-id", validCode)
	require.NoError(t, err)
	assert.False(t, notValid)

	totpID2, uri2, err := p.GenerateTOTP("totp", "i", "a1", "a1-id")
	require.NoError(t, err)
	assert.NotEqual(t, totpID, totpID2)
	assert.NotEqual(t, uri, uri2)

	client2, err := totp.ParseFromURI(uri2)
	require.NoError(t, err)
	require.NotNil(t, client2)

	validCode2, err := client2.Generate()
	require.NoError(t, err)
	require.NotEqual(t, validCode, validCode2)

	notValid, err = p.VerifyTOTP("totp", totpID, "a1-id", validCode2)
	require.NoError(t, err)
	assert.False(t, notValid)
}
