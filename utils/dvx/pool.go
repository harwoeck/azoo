package dvx

import (
	"encoding/base64"

	logger "github.com/harwoeck/liblog/contract"
)

// KeyPool is an interface for a key derivation loader.
type KeyPool interface {
	// KDF32 is a key derivation function that returns a 32-byte key for the
	// keyRing passed to it. Equal keyRings must always result in equal keys.
	KDF32(keyRing []byte) (key []byte, err error)
	// KDF64 is a key derivation function that returns a 64-byte key for the
	// keyRing passed to it. Equal keyRings must always result in equal keys.
	KDF64(keyRing []byte) (key []byte, err error)
	// Close closes the KeyPool and it's underlying instances.
	Close() error
}

// WrapDVXAsKeyPool provides a KeyPool implementation by using the
// Primitive.MAC256 and Primitive.MAC512 functions as key-derivation-functions.
// The passed rootKey is used as key for the MAC-constructions. A passed keyRing
// is used a message during derivation.
func WrapDVXAsKeyPool(dvx Primitive, rootKey []byte, log logger.Logger) KeyPool {
	return &dvxWrapper{dvx, rootKey, log.Named("dvx_keypool").Named("audit")}
}

type dvxWrapper struct {
	dvx      Primitive
	rootKey  []byte
	auditLog logger.Logger
}

func (d *dvxWrapper) kdf(keyRing []byte, mac func(key []byte, data []byte) (tag []byte, err error)) (key []byte, err error) {
	key, err = mac(d.rootKey, keyRing)
	if err != nil {
		return nil, err
	}

	d.auditLog.Info("loaded key",
		logger.NewField("key_len", len(key)),
		logger.NewField("key_ring", base64.RawStdEncoding.EncodeToString(keyRing)),
		logger.NewField("key_ring_str", string(keyRing)))
	return
}

func (d *dvxWrapper) KDF32(keyRing []byte) (key []byte, err error) {
	return d.kdf(keyRing, d.dvx.MAC256)
}

func (d *dvxWrapper) KDF64(keyRing []byte) (key []byte, err error) {
	return d.kdf(keyRing, d.dvx.MAC512)
}

func (d *dvxWrapper) Close() error {
	d.rootKey = nil
	return nil
}
