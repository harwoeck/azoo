package tearc

import (
	"time"
)

type heapItem struct {
	key          string
	evictionTime time.Time
	index        int
}

// evictionQueue implements a heap.Interface and holds references to the next
// cache item that needs to be evicted
type evictionQueue []*heapItem

func (eq evictionQueue) Len() int {
	return len(eq)
}

func (eq evictionQueue) Less(i, j int) bool {
	// we want Pop to give use the lowest remaining eviction time
	return eq[i].evictionTime.Before(eq[j].evictionTime)
}

func (eq evictionQueue) Swap(i, j int) {
	eq[i], eq[j] = eq[j], eq[i]
	eq[i].index = i
	eq[j].index = j
}

func (eq *evictionQueue) Push(x interface{}) {
	n := len(*eq)
	item := x.(*heapItem)
	item.index = n
	*eq = append(*eq, item)
}

func (eq *evictionQueue) Pop() interface{} {
	old := *eq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*eq = old[0 : n-1]
	return item
}
