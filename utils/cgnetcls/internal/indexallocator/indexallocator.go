// The index allocator is a singleton because this reflects the marks assigned on the filesystem

package indexallocator

import (
	"errors"
	"sync"
)

type allocator struct {
	size           int
	startIndex     int
	availableMarks map[int]struct{}
	sync.Mutex
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
			size:           size,
			startIndex:     startIndex,
			availableMarks: make(map[int]struct{}, size),
		}
		for i := startIndex; i < startIndex+size; i++ {
			indexes.availableMarks[i] = struct{}{}
		}
	})
	return indexes, size, startIndex
}

// Get gets an index from the allocator
func (i *allocator) Get() int {
	i.Lock()
	defer i.Unlock()
	for k := range i.availableMarks {
		delete(i.availableMarks, k)
		return k
	}
	return -1
}

// Put returns back an index to the allocator
func (i *allocator) Put(index int) error {
	i.Lock()
	defer i.Unlock()
	if index < i.startIndex || index > i.startIndex+i.size {
		return errors.New("Index outside managed range")
	}
	i.availableMarks[index] = struct{}{}
	return nil
}
