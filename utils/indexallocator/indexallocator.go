package indexallocator

import (
	"sync"
)

type allocator struct {
	size         int
	startIndex   int
	indexChannel chan int
}

var indexes *allocator = &allocator{
	size:       0,
	startIndex: 0,
}
var once sync.Once

// New create a new indexallocator
func New(size int, startIndex int) (IndexAllocator, int, int) {

	if indexes.size != 0 {
		return indexes, indexes.size, indexes.startIndex
	}
	once.Do(func() {
		indexes = &allocator{
			size:         size,
			startIndex:   startIndex,
			indexChannel: make(chan int, size),
		}
		for i := startIndex; i < startIndex+size; i++ {
			indexes.indexChannel <- i
		}
	})
	return indexes, size, startIndex
}

// Get gets an index from the allocator
func (i *allocator) Get() int {
	return <-i.indexChannel
}

// Put returns back an index to the allocator
func (i *allocator) Put(index int) {
	i.indexChannel <- index
}
