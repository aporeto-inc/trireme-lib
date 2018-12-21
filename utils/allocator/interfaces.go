package allocator

// Allocator is an allocator interface
type Allocator interface {

	// Allocate allocates a string
	Allocate() string

	// Release releases a string
	Release(item string)

	// AllocateInt allocates an int
	AllocateInt() int

	// ReleaseInt releases an item of type integer.
	ReleaseInt(item int)
}
