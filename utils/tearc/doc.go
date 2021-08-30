// Package tearc provides a sharded caching data structure with sliding frame
// (e.g. timing) evictions and adaptive replacement caching. Its goal is to
// keep as few high-security objects (private keys) in memory as possible.
// Items are either evicted when chosen by page replacement (ARC) or at latest
// when their eviction time has come (a Go heap with sliding frames reaches it).
//
// This results in a caching data structure that has at max n-items chosen by
// adaptive replacement caching, but fully clears its memory after the
// configured eviction time. The eviction time resets after every usage (Get)
// of the cached item.
//
// tearc internally uses sharded caches to minimize mutex contention. This
// performs slightly worse on small caches, but improves stable performance in
// more congested times.
//
// tearc stands for Timed-Eviction-Adaptive-Replacement-Cache
package tearc
