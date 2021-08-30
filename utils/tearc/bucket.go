package tearc

import (
	"container/heap"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bluele/gcache"
	logger "github.com/harwoeck/liblog/contract"
)

type BucketConfig struct {
	// MinTick is the minimum amount of time between bucket reaper runs.
	// For example: 1 * time.Second
	MinTick time.Duration
	// MaxTick is the maximum amount of time between bucket reaper runs.
	// For example: 10 * time.Second
	MaxTick time.Duration
}

type bucket struct {
	id        int
	log       logger.Logger
	loader    LoaderFunc
	evicted   EvictedFunc
	config    *BucketConfig
	arc       gcache.Cache
	eq        evictionQueue
	eqPtrMap  map[string]*heapItem
	eqLock    sync.Mutex
	closeOnce sync.Once
	closeSig  chan struct{}
}

func (b *bucket) loadAndSet(key string, loadInfo interface{}) (interface{}, error) {
	value, evictIn, err := b.loader(key, loadInfo)
	if err != nil {
		return nil, fmt.Errorf("tearc: unable to load value with LoaderFunc: %w", err)
	}

	err = b.arc.Set(key, value)
	if err != nil {
		return nil, fmt.Errorf("tearc: failed to set value to arc cache: %w", err)
	}

	evictionTime := time.Now().UTC().Add(evictIn)
	func() {
		b.eqLock.Lock()
		defer b.eqLock.Unlock()

		item := &heapItem{
			key:          key,
			evictionTime: evictionTime,
		}

		b.eqPtrMap[key] = item
		heap.Push(&b.eq, item)
	}()

	return value, nil
}

func (b *bucket) Get(key string, loadInfo interface{}) (interface{}, error) {
	value, err := b.arc.Get(key)
	if err != nil {
		if errors.Is(err, gcache.KeyNotFoundError) {
			return b.loadAndSet(key, loadInfo)
		}

		return nil, fmt.Errorf("tearc: getting value errored: %w", err)
	}

	go func(evictionTime time.Time) {
		b.eqLock.Lock()
		defer b.eqLock.Unlock()

		item := b.eqPtrMap[key]
		if item == nil {
			return
		}

		item.evictionTime = evictionTime
		heap.Fix(&b.eq, item.index)
	}(time.Now().UTC().Add(1 * time.Minute))

	return value, nil
}

func (b *bucket) Close() {
	b.closeOnce.Do(func() {
		b.closeSig <- struct{}{}

		b.eqLock.Lock()
		defer b.eqLock.Unlock()

		b.arc.Purge()
		b.arc = nil
		b.eq = nil
		b.eqPtrMap = nil
	})
}

func (b *bucket) startReaper() {
	reap := func() time.Duration {
		b.eqLock.Lock()
		defer b.eqLock.Unlock()

		for b.eq.Len() > 0 {
			// pop one item from the heap
			item := heap.Pop(&b.eq).(*heapItem)

			// if item isn't yet ready for eviction -> push it again to the heap
			// and return duration timeout for it
			now := time.Now().UTC()
			if now.Before(item.evictionTime) {
				heap.Push(&b.eq, item)
				timeout := item.evictionTime.Sub(now) + 50*time.Millisecond

				b.log.Debug("next item in eviction queue isn't ready",
					logger.NewField("next_item", item.key),
					logger.NewField("eviction_time", item.evictionTime),
					logger.NewField("timeout", timeout))

				return timeout
			}

			b.log.Debug("next item in eviction queue is evicted now",
				logger.NewField("next_item", item.key),
				logger.NewField("eviction_time", item.evictionTime))

			// remove item from arc cache and call evicted information
			// callback in new go routine
			if b.arc.Remove(item.key) {
				go b.evicted(item.key)
			}

			// remove from pointer map
			delete(b.eqPtrMap, item.key)
		}

		return b.config.MinTick
	}

	b.closeSig = make(chan struct{})
	go func() {
		t := time.NewTicker(b.config.MinTick)

		for {
			select {
			case <-t.C:
				next := reap()
				if next < b.config.MinTick {
					next = b.config.MinTick
				} else if next > b.config.MaxTick {
					next = b.config.MaxTick
				}
				t.Reset(next)
			case <-b.closeSig:
				t.Stop()
				return
			}
		}
	}()
}
