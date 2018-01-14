package contextstore

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testcontextID = "/test"
	storebasePath = "./base"
)

type testdatastruct struct {
	Data int
}

func cleanupstore(storebasePath string) {
	os.RemoveAll(storebasePath) //nolint
}

func TestStore(t *testing.T) {
	cstore := NewFileContextStore("./base", nil)
	defer cleanupstore("./base")

	testdata := &testdatastruct{Data: 10}
	marshaldata, _ := json.Marshal(testdata)
	err := cstore.Store(testcontextID, testdata)
	if err != nil {
		t.Errorf("Failed to store context data %s", err.Error())
		t.SkipNow()
	} else {

		readdata, _ := ioutil.ReadFile(filepath.Join("./base", testcontextID, itemFile))

		if strings.TrimSpace(string(readdata)) != string(marshaldata) {
			t.Errorf("Data corrupted in stores - %s - %s", strings.TrimSpace(string(readdata)), string(marshaldata))
			t.SkipNow()
		}
	}
}

func TestDestroyStore(t *testing.T) {

	cstore := NewFileContextStore(storebasePath, nil)
	defer cleanupstore("./base")

	os.RemoveAll(storebasePath) //nolint
	if err := cstore.DestroyStore(); err == nil {
		t.Errorf("No Error returned for uninited store")
		t.SkipNow()
	}

	//Reinit store
	cstore = NewFileContextStore(storebasePath, nil)
	testdata := &testdatastruct{Data: 10}
	if err := cstore.Store(testcontextID, testdata); err != nil {
		t.Errorf("Failed to store context %s", err.Error())
	}

	if err := cstore.DestroyStore(); err != nil {
		t.Errorf("Unable to destroy contextstore %s", err.Error())
		t.SkipNow()
	}
}

func TestRetrieve(t *testing.T) {

	cstore := NewFileContextStore(storebasePath, nil)
	defer cleanupstore("./base")

	context := testdatastruct{}

	err := cstore.Retrieve(testcontextID, &context)
	if err == nil {
		t.Errorf("No error returned for non-existent context")
		t.SkipNow()
	}

	testdata := &testdatastruct{Data: 10}
	if cerr := cstore.Store(testcontextID, testdata); cerr != nil {
		t.Errorf("Cannot store data %s ", cerr.Error())
	}

	if err := cstore.Retrieve(testcontextID, &context); err != nil {
		t.Errorf("Unable to get contextinfo %s", err.Error())
		t.SkipNow()
	} else {
		if testdata.Data != context.Data {
			t.Errorf("Data recovered does not match written data")
			t.SkipNow()
		}
	}
}

func TestRemove(t *testing.T) {

	cstore := NewFileContextStore(storebasePath, nil)
	defer cleanupstore("./base")

	err := cstore.Remove(testcontextID)
	if err == nil {
		t.Errorf("No Error returned for non-existent context")
		t.SkipNow()
	}
	testdata := &testdatastruct{Data: 10}
	if cerr := cstore.Store(testcontextID, testdata); cerr != nil {
		t.Errorf("Cannot store data %s ", cerr.Error())
	}
	if err = cstore.Remove(testcontextID); err != nil {
		t.Errorf("Failed to remove context from store %s", err.Error())
		t.SkipNow()
	} else {
		_, staterr := os.Stat(filepath.Join(storebasePath, testcontextID))
		if staterr == nil {
			t.Errorf("Failed to remove context %s", staterr.Error())
			t.SkipNow()
		}
	}
}

func TestWalk(t *testing.T) {

	cstore := NewFileContextStore(storebasePath, nil)
	defer cleanupstore("./base")
	testdata := &testdatastruct{Data: 10}
	contextIDList := []string{"/test1", "/test2", "/test3"}

	for _, contextID := range contextIDList {
		if err := cstore.Store(contextID, testdata); err != nil {
			t.Errorf("Cannot store data %s ", err.Error())
		}
	}
	contextchan, _ := cstore.Walk()
	index := 0
	for {
		c := <-contextchan
		if c == "" {
			break
		}
		index = index + 1
	}
	if index != len(contextIDList) {
		t.Errorf("Walk did not get all contextIDs %d", index)
		t.SkipNow()
	}
}
