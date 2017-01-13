package contextstore

type ContextStore interface {
	StoreContext(contextID string, eventInfo interface{}) error
	DestroyStore() error
	GetContextInfo(contextID string) (interface{}, error)
	RemoveContext(contextID string) error
	WalkStore() (chan string, error)
}
