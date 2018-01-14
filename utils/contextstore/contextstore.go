package contextstore

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type store struct {
	storebasePath    string
	dataErrorHandler func(string, interface{}) error
}

const (
	itemFile = "eventInfo.data"
)

func checkAndCreateDir(folder string) error {

	_, err := os.Stat(folder)
	if err == nil {
		return nil
	}

	if !os.IsNotExist(err) {
		return err
	}

	return os.MkdirAll(folder, 0700)
}

// NewFileContextStore is an implementation of ContextStore using a file. Each context is
// stored in its directory identified by id in a file called eventInfo.data
func NewFileContextStore(basePath string, onDataFormatError func(string, interface{}) error) ContextStore {

	if err := checkAndCreateDir(basePath); err != nil {
		return nil
	}

	return &store{
		storebasePath:    basePath,
		dataErrorHandler: onDataFormatError,
	}
}

// Store stores a context in a file
func (s *store) Store(contextID string, item interface{}) error {

	folder := filepath.Join(s.storebasePath, contextID)
	if err := checkAndCreateDir(folder); err != nil {
		return err
	}

	data, err := json.Marshal(item)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(folder, itemFile), data, 0600)
}

// Retrieve retrieves a context from the file
func (s *store) Retrieve(contextID string, context interface{}) error {

	folder := filepath.Join(s.storebasePath, contextID)

	if _, err := os.Stat(folder); os.IsNotExist(err) {
		return fmt.Errorf("unknown contextid: %s", contextID)
	}

	data, err := ioutil.ReadFile(filepath.Join(folder, itemFile))

	if err != nil {
		return fmt.Errorf("unable to retrieve context from store: %s", err)
	}

	if err = json.Unmarshal(data, context); err != nil {
		if s.dataErrorHandler != nil {
			if err := s.dataErrorHandler(string(data), context); err == nil {
				s.Store(contextID, context)
				return nil
			} 
		}
		if err = s.Remove(contextID); err != nil {
			return fmt.Errorf("invalid format of data detected, cleanup failed: %s", err)
		}
		return fmt.Errorf("invalid format of data: %s", err)
	}

	return nil
}

// Remove the context reference from the store
func (s *store) Remove(contextID string) error {

	folder := filepath.Join(s.storebasePath, contextID)
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		return fmt.Errorf("unknown context id: %s", contextID)
	}

	return os.RemoveAll(folder)
}

// Destroy will clean up the entire state for all services in the system
func (s *store) DestroyStore() error {

	if _, err := os.Stat(s.storebasePath); os.IsNotExist(err) {
		return fmt.Errorf("store not initialized: %s", err)
	}

	return os.RemoveAll(s.storebasePath)
}

// Walk retrieves all the context store information and returns it in a channel
func (s *store) Walk() (chan string, error) {

	files, err := ioutil.ReadDir(s.storebasePath)
	if err != nil {
		return nil, fmt.Errorf("store is empty: %s", err)
	}

	contextChannel := make(chan string, 1)

	go func() {
		i := 0
		for _, file := range files {
			contextChannel <- file.Name()
			i++
		}

		contextChannel <- ""
		close(contextChannel)
	}()

	return contextChannel, nil
}
