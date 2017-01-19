package contextstore

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/Sirupsen/logrus"
)

type store struct{}

var (
	storebasePath = "/var/run/aporeto"
)

const (
	eventInfoFile = "/eventInfo.data"
)

//NewContextStore returns a handle to a new context store
//The store is maintained in a file hierarchy so if the context id
//already exists calling a storecontext with new id will cause an overwrite
func NewContextStore() ContextStore {

	_, err := os.Stat(storebasePath)
	if os.IsNotExist(err) {
		os.MkdirAll(storebasePath, 0700)
	}
	return &store{}
}

func setStoreBasePath(path string) {
	storebasePath = path
}

//Store context writes to the store the eventInfo which can be used as a event to trireme
func (s *store) StoreContext(contextID string, eventInfo interface{}) error {

	if _, err := os.Stat(storebasePath + contextID); os.IsNotExist(err) {
		os.MkdirAll(storebasePath+contextID, 0700)
	}

	data, err := json.Marshal(eventInfo)
	if err != nil {
		log.WithFields(log.Fields{"package": "contextstore",
			"error": err.Error(),
		}).Debug(" JSON conversion failed for eventinfo")
		return fmt.Errorf("Failed to convert struct to json %s\n", err.Error())
	}

	if err = ioutil.WriteFile(storebasePath+contextID+eventInfoFile, data, 0600); err != nil {
		return err
	}
	return nil

}

//GetContextInfo the event corresponding to the store
func (s *store) GetContextInfo(contextID string) (interface{}, error) {

	if _, err := os.Stat(storebasePath + contextID); os.IsNotExist(err) {
		log.WithFields(log.Fields{"package": "contextstore",
			"Error": err.Error(),
		}).Debug("ContextID not known")
		return nil, fmt.Errorf("Unknown ContextID %s", contextID)
	}

	data, err := ioutil.ReadFile(storebasePath + contextID + eventInfoFile)
	if err != nil {
		log.WithFields(log.Fields{"package": "contextstore",
			"Error": err.Error(),
		}).Debug("Unable to read eventInfo file")
		return nil, fmt.Errorf("Unable to retrieve context from store %s", err.Error())
	}

	return data, err
}

//RemoveContext the context reference from the store
func (s *store) RemoveContext(contextID string) error {

	if _, err := os.Stat(storebasePath + contextID); os.IsNotExist(err) {
		log.WithFields(log.Fields{"package": "contextstore",
			"Error": err.Error(),
		}).Debug("ContextID not known")
		return fmt.Errorf("Unknown ContextID %s", contextID)
	}

	return os.RemoveAll(storebasePath + contextID)

}

//Destroy will clean up the entire state for all services in the system
func (s *store) DestroyStore() error {

	if _, err := os.Stat(storebasePath); os.IsNotExist(err) {
		log.WithFields(log.Fields{"package": "contextstore",
			"Error": err.Error(),
		}).Debug("Store not initialized")

		return fmt.Errorf("Store Not Initialized")
	}
	return os.RemoveAll(storebasePath)
}

func (s *store) WalkStore() (chan string, error) {

	contextChannel := make(chan string, 1)
	files, err := ioutil.ReadDir(storebasePath)
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
