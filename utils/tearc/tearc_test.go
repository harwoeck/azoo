package tearc

import (
	"fmt"
	"testing"
	"time"

	"github.com/harwoeck/liblog/contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimple(t *testing.T) {
	evicted1 := false
	evicted2 := false

	load1 := false
	load2 := false

	cache, err := NewCache(1000, 4, func(key string, loadInfo interface{}) (value interface{}, evictIn time.Duration, err error) {
		switch key {
		case "key1":
			load1 = true
			return []byte("private key 1"), 1 * time.Second, nil
		case "key2":
			load2 = true
			return []byte("private key 2"), 1 * time.Second, nil
		default: return nil, 0, fmt.Errorf("unknown key")
		}
	}, func(key string) {
		switch key {
		case "key1": evicted1 = true
		case "key2": evicted2 = true
		}
	}, &BucketConfig{
		MinTick: 500 * time.Millisecond,
		MaxTick: 3 * time.Second,
	}, contract.MustNewStd())
	require.NoError(t, err)
	defer cache.Close()

	// verify load key 1
	x, err := cache.Get("key1", nil)
	require.NoError(t, err)
	assert.True(t, load1)
	buf, ok := x.([]byte)
	assert.True(t, ok)
	assert.Equal(t, "private key 1", string(buf))

	// verify load key 2
	y, err := cache.Get("key2", nil)
	require.NoError(t, err)
	assert.True(t, load2)
	buf, ok = y.([]byte)
	assert.True(t, ok)
	assert.Equal(t, "private key 2", string(buf))

	// verify key2 is cached
	load2 = false
	x, err = cache.Get("key2", nil)
	require.NoError(t, err)
	assert.False(t, load2)
	buf, ok = x.([]byte)
	assert.True(t, ok)
	assert.Equal(t, "private key 2", string(buf))

	// sleep
	time.Sleep(2 * time.Second)

	// verify correct evictions
	assert.True(t, evicted1)
	assert.False(t, evicted2)
}
