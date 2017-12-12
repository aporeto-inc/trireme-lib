package allocator

// Allocator is an allocator interface
type Allocator interface {

	// Allocate allocates a string
	Allocate() string

	// Release releases a string
	Release(item string)
}
