package indexallocator

// IndexAllocator provides an interfaces to get an index and return an index to the alllocator
type IndexAllocator interface {
	Get() int
	Put(index int) error
}
