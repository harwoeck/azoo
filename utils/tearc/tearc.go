package tearc

import (
	"fmt"
	"hash/maphash"
	"sync"
	"time"

	"github.com/bluele/gcache"
	logger "github.com/harwoeck/liblog/contract"
)

// Cache represents a single tearc instance
type Cache interface {
	Get(key string, loadInfo interface{}) (interface{}, error)
	Close()
}

// LoaderFunc represents a callback to load a non-existing value into the
// cache. info is the loadInfo object passed to Cache.Get.
type LoaderFunc func(key string, info interface{}) (value interface{}, evictIn time.Duration, err error)

// EvictedFunc is an information callback that is called after an item has been
// evicted from the cache.
type EvictedFunc func(key string)

// NewCache creates a new tearc instance
func NewCache(size int, shards int, loader LoaderFunc, evicted EvictedFunc, config *BucketConfig, log logger.Logger) (Cache, error) {
	log = log.Named("tearc")

	if size <= 0 {
		return nil, fmt.Errorf("tearc: size cannot be %d! Must be greater than zero", size)
	}
	if shards <= 0 {
		return nil, fmt.Errorf("tearc: shards cannot be %d! Must be greater than zero", shards)
	}
	if size%shards != 0 {
		return nil, fmt.Errorf("tearc: size must be easily dividable into shards")
	}
	if loader == nil {
		return nil, fmt.Errorf("tearc: loader must not be nil")
	}
	if evicted == nil {
		// set to empty callback
		evicted = func(_ string) {}
	}
	if config == nil {
		return nil, fmt.Errorf("tearc: config must not be nil")
	} else {
		if config.MinTick >= config.MaxTick {
			return nil, fmt.Errorf("tearc: config.MinTick must be less than config.MustTick")
		}
	}

	t := &tearc{
		size:   size,
		shards: uint64(shards),
		hasherPool: sync.Pool{
			New: func() interface{} {
				return &maphash.Hash{}
			}},
		jumpSeed: maphash.MakeSeed(),
	}

	t.buckets = make([]*bucket, shards)
	for i := 0; i < shards; i++ {
		t.buckets[i] = &bucket{
			id:       i,
			log:      log.Named(fmt.Sprintf("bucket-%d", i)),
			loader:   loader,
			evicted:  evicted,
			config:   config,
			arc:      gcache.New(size / shards).ARC().Build(),
			eq:       make(evictionQueue, 0),
			eqPtrMap: make(map[string]*heapItem),
		}

		go t.buckets[i].startReaper()
	}

	return t, nil
}

type tearc struct {
	size   int
	shards uint64

	hasherPool sync.Pool
	jumpSeed   maphash.Seed
	buckets    []*bucket
}

func (t *tearc) jump(key string) *bucket {
	h := t.hasherPool.Get().(*maphash.Hash)
	defer func() {
		h.Reset()
		t.hasherPool.Put(h)
	}()
	h.SetSeed(t.jumpSeed)
	_, _ = h.WriteString(key)
	jumpIdx := h.Sum64() % t.shards
	return t.buckets[jumpIdx]
}

func (t *tearc) Get(key string, loadInfo interface{}) (interface{}, error) {
	return t.jump(key).Get(key, loadInfo)
}

func (t *tearc) Close() {
	for _, b := range t.buckets {
		b.Close()
	}
}
