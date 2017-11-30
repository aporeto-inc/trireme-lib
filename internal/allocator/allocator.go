package allocator

import "strconv"

// allocator
type allocator struct {
	allocate chan string
}

// New provides a new allocator
func New(start, size int) Allocator {

	a := &allocator{
		allocate: make(chan string, size),
	}

	for i := start; i < (start + size); i++ {
		a.allocate <- strconv.Itoa(i)
	}

	return a
}

// Allocate allocates an item
func (p *allocator) Allocate() string {
	return <-p.allocate
}

// Release releases an item
func (p *allocator) Release(item string) {
	p.allocate <- item
}
