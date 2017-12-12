package contextstore

// ContextStore is the interface defining the context store
type ContextStore interface {

	// Store stores a contextID and eventInfo in the store
	Store(id string, item interface{}) error

	// Retrieve retrieves the context given a context ID
	Retrieve(id string, item interface{}) error

	// Remove removes the context given a context ID
	Remove(id string) error

	// Walk walks the whole store and returns a channel for the values
	Walk() (chan string, error)

	// DestroyStore destroys the store
	DestroyStore() error
}
