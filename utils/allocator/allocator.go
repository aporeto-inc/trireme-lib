package allocator

import (
	"strconv"
)

// allocator
type allocator struct {
	allocate chan int
}

// New provides a new allocator
func New(start, size int) Allocator {
	a := &allocator{
		allocate: make(chan int, size),
	}

	for i := start; i < (start + size); i++ {
		a.allocate <- i
	}

	return a
}

// Allocate allocates an item
func (p *allocator) Allocate() string {
	return strconv.Itoa(<-p.allocate)
}

// Release releases an item
func (p *allocator) Release(item string) {

	// Do not release when the channel is full. These can happen when we resync
	// stopped containers.
	if len(p.allocate) == cap(p.allocate) {
		return
	}

	intItem, err := strconv.Atoi(item)
	if err != nil {
		return
	}
	p.allocate <- intItem
}

// AllocateInt allocates an integer.
func (p *allocator) AllocateInt() int {
	return <-p.allocate
}

// ReleaseInt releases an int.
func (p *allocator) ReleaseInt(item int) {
	if len(p.allocate) == cap(p.allocate) || item == 0 {
		return
	}

	p.allocate <- item
}
