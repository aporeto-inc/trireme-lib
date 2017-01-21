package contextstore

// ContextStore is the interface defining the context store
type ContextStore interface {

	// StoreContext stores a contextID and eventInfo in the store
	StoreContext(contextID string, eventInfo interface{}) error

	// DestroyStore destroys the store
	DestroyStore() error

	// GetContextInfo retrieves the context given a context ID
	GetContextInfo(contextID string) (interface{}, error)

	// RemoveContext removes the context given a context ID
	RemoveContext(contextID string) error

	// WalkStore walks the whole store and returns a channel for the values
	WalkStore() (chan string, error)
}
