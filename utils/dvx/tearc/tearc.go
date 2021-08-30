// Package tearc provides a KeyPool implementation that acts as an intermediate
// caching layer, by wrapping another underlying KeyPool that actually derives
// the keys. This reduces calls to the root KeyPool and therefore improves
// performance for hot-path (often-used) keys drastically. The underlying cache
// data structure is a (azoo.dev/utils/tearc).Cache (tearc standing for
// Timed-Eviction-Adaptive-Replacement-Cache), which tries to remove unused
// keys from memory as soon as possible.
//
// The caching data structure itself is moved into a standalone utils module,
// so it can be used and imported by other projects easily.
package tearc

import (
	"time"

	logger "github.com/harwoeck/liblog/contract"

	"azoo.dev/utils/tearc"
)

// KeyPool is an interface for a key derivation loader. It is copied from the
// parent project azoo.dev/utils/dvx
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

// Config provides all options for a tearc KeyPool. Every field is required.
// Not providing valid configuration values results in unspecified behaviour.
// No checks are carried out!
type Config struct {
	// Size is the size of the underlying tearc Cache. For example: 65536
	Size int
	// Shards is the amount of shards used in the underlying tearc Cache. For
	// example: 64
	Shards int
	// BucketMinTick is the minimum amount of time between bucket reaper runs.
	// For example: 1 * time.Second
	BucketMinTick time.Duration
	// BucketMaxTick is the maximum amount of time between bucket reaper runs.
	// For example: 10 * time.Second
	BucketMaxTick time.Duration
	// AliveTime specifies how long cached keys should stay alive (in RAM) at
	// maximum. They may get replaced sooner by page replacement (ARC). For
	// example: 1 * time.Minute
	AliveTime time.Duration
}

// New creates a new tearc Cache and wraps it as a KeyPool instance with the
// underlying KeyPool `pool` as actual loader.
func New(config *Config, pool KeyPool, log logger.Logger) (KeyPool, error) {
	w := &wrapper{
		log:    log.Named("tearc"),
		config: config,
		src:    pool,
	}

	var err error
	w.cache, err = tearc.NewCache(config.Size, config.Shards, w.get, w.evict,
		&tearc.BucketConfig{
			MinTick: config.BucketMinTick,
			MaxTick: config.BucketMaxTick,
		}, log)
	if err != nil {
		return nil, err
	}

	return w, nil
}

type wrapper struct {
	log    logger.Logger
	config *Config
	src    KeyPool
	cache  tearc.Cache
}

func (w *wrapper) get(key string, loadInfo interface{}) (value interface{}, evictIn time.Duration, err error) {
	switch loadInfo.(int) {
	case 32:
		w.log.Debug("loading 32 byte key", logger.NewField("key", key))
		value, err = w.src.KDF32([]byte(key))
	case 64:
		w.log.Debug("loading 64 byte key", logger.NewField("key", key))
		value, err = w.src.KDF64([]byte(key))
	}
	if err != nil {
		return nil, 0, err
	}

	evictIn = w.config.AliveTime
	return
}

func (w *wrapper) evict(key string) {
	w.log.Info("evicted key from cache", logger.NewField("key", key))
}

func (w *wrapper) KDF32(keyRing []byte) (key []byte, err error) {
	value, err := w.cache.Get(string(keyRing), 32)
	if err != nil {
		return nil, err
	}
	return value.([]byte), nil
}

func (w *wrapper) KDF64(keyRing []byte) (key []byte, err error) {
	value, err := w.cache.Get(string(keyRing), 64)
	if err != nil {
		return nil, err
	}
	return value.([]byte), nil
}

func (w *wrapper) Close() error {
	return w.src.Close()
}
