package contextstore

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"go.uber.org/zap"
)

type store struct {
	storebasePath string
}

var (
	storebasePath = "/var/run/trireme"
)

const (
	eventInfoFile = "/eventInfo.data"
)

// NewContextStore returns a handle to a new context store
// The store is maintained in a file hierarchy so if the context id
// already exists calling a storecontext with new id will cause an overwrite
func NewContextStore(basePath string) ContextStore {

	_, err := os.Stat(basePath)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(basePath, 0700); err != nil {
			zap.L().Fatal("Failed to create context store directory", zap.Error(err))
		}
	}

	return &store{storebasePath: basePath}
}

// NewCustomContextStore will start a context store with custom paths. Mainly
// used for testing when root access is not available and /var/run cannot be accessed
func NewCustomContextStore(basePath string) ContextStore {
	//storebasePath = basePath
	return NewContextStore(basePath)
}

// Store context writes to the store the eventInfo which can be used as a event to trireme
func (s *store) StoreContext(contextID string, eventInfo interface{}) error {

	if _, err := os.Stat(s.storebasePath + contextID); os.IsNotExist(err) {
		if err := os.MkdirAll(s.storebasePath+contextID, 0700); err != nil {
			return err
		}
	}

	data, err := json.Marshal(eventInfo)
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(s.storebasePath+contextID+eventInfoFile, data, 0600); err != nil {
		return err
	}

	return nil

}

// GetContextInfo the event corresponding to the store
func (s *store) GetContextInfo(contextID string) (interface{}, error) {

	if _, err := os.Stat(s.storebasePath + contextID); os.IsNotExist(err) {
		return nil, fmt.Errorf("Unknown ContextID %s", contextID)
	}

	data, err := ioutil.ReadFile(s.storebasePath + contextID + eventInfoFile)
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve context from store %s", err.Error())
	}

	return data, err
}

// RemoveContext the context reference from the store
func (s *store) RemoveContext(contextID string) error {

	if _, err := os.Stat(s.storebasePath + contextID); os.IsNotExist(err) {
		return fmt.Errorf("Unknown ContextID %s", contextID)
	}

	return os.RemoveAll(s.storebasePath + contextID)

}

// Destroy will clean up the entire state for all services in the system
func (s *store) DestroyStore() error {

	if _, err := os.Stat(s.storebasePath); os.IsNotExist(err) {
		return fmt.Errorf("Store Not Initialized")
	}

	return os.RemoveAll(s.storebasePath)
}

// WalkStore retrieves all the context store information and returns it in a channel
func (s *store) WalkStore() (chan string, error) {

	contextChannel := make(chan string, 1)

	files, err := ioutil.ReadDir(s.storebasePath)
	if err != nil {
		close(contextChannel)
		return contextChannel, fmt.Errorf("Store is empty")
	}

	go func() {
		for _, file := range files {
			contextChannel <- file.Name()
		}
		contextChannel <- ""
		close(contextChannel)
	}()

	return contextChannel, nil
}
