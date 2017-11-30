package contextstore

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

type store struct {
	storebasePath string
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
func NewFileContextStore(basePath string) ContextStore {

	if err := checkAndCreateDir(basePath); err != nil {
		return nil
	}

	return &store{
		storebasePath: basePath,
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

	if err = ioutil.WriteFile(filepath.Join(folder, itemFile), data, 0600); err != nil {
		return err
	}

	return nil
}

// Retrieve retrieves a context from the file
func (s *store) Retrieve(contextID string, context interface{}) error {

	folder := filepath.Join(s.storebasePath, contextID)

	if _, err := os.Stat(folder); os.IsNotExist(err) {
		return fmt.Errorf("Unknown ContextID %s", contextID)
	}

	data, err := ioutil.ReadFile(filepath.Join(folder, itemFile))
	if err != nil {
		return fmt.Errorf("Unable to retrieve context from store %s", err.Error())
	}

	if err = json.Unmarshal(data, context); err != nil {
		if err = s.Remove(contextID); err != nil {
			return fmt.Errorf("Invalid format of data detected, cleanup failed %s", err.Error())
		}
		return fmt.Errorf("Invalid format of data %s", err.Error())
	}

	return nil
}

// Remove the context reference from the store
func (s *store) Remove(contextID string) error {

	folder := filepath.Join(s.storebasePath, contextID)
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		return fmt.Errorf("Unknown ContextID %s", contextID)
	}

	return os.RemoveAll(folder)
}

// Destroy will clean up the entire state for all services in the system
func (s *store) DestroyStore() error {

	if _, err := os.Stat(s.storebasePath); os.IsNotExist(err) {
		return fmt.Errorf("Store Not Initialized")
	}

	return os.RemoveAll(s.storebasePath)
}

// Walk retrieves all the context store information and returns it in a channel
func (s *store) Walk() (chan string, error) {

	files, err := ioutil.ReadDir(s.storebasePath)
	if err != nil {
		return nil, fmt.Errorf("Store is empty")
	}

	contextChannel := make(chan string, 1)

	go func() {
		i := 0
		for _, file := range files {
			zap.L().Debug("File Name", zap.String("Path", file.Name()))
			contextChannel <- file.Name()
			i++
		}

		contextChannel <- ""
		close(contextChannel)
	}()

	return contextChannel, nil
}
