package contextstore

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

const (
	testcontextID = "/test"
)

type testdatastruct struct {
	data int
}

func cleanupstore() {
	os.RemoveAll(storebasePath) //nolint
}

func TestStoreContext(t *testing.T) {
	cstore := NewCustomContextStore("./base")
	defer cleanupstore()

	testdata := &testdatastruct{data: 10}
	marshaldata, _ := json.Marshal(testdata)
	err := cstore.StoreContext(testcontextID, testdata)
	if err != nil {
		t.Errorf("Failed to store context data %s", err.Error())
		t.SkipNow()
	} else {

		readdata, _ := ioutil.ReadFile("./base/" + testcontextID + eventInfoFile)

		if strings.TrimSpace(string(readdata)) != string(marshaldata) {
			t.Errorf("Data corrupted in stores")
			t.SkipNow()
		}
	}
}

func TestDestroyStore(t *testing.T) {
	storebasePath = "./base"
	cstore := NewContextStore(storebasePath)
	defer cleanupstore()

	os.RemoveAll(storebasePath) //nolint
	if err := cstore.DestroyStore(); err == nil {
		t.Errorf("No Error returned for uninited store")
		t.SkipNow()
	}
	//Reinit store
	storebasePath = "./base"
	cstore = NewContextStore(storebasePath)
	testdata := &testdatastruct{data: 10}
	if err := cstore.StoreContext(testcontextID, testdata); err != nil {
		t.Errorf("Failed to store context %s", err.Error())
	}

	if err := cstore.DestroyStore(); err != nil {
		t.Errorf("Unable to destroy contextstore %s", err.Error())
		t.SkipNow()
	}
}

func TestGetContextInfo(t *testing.T) {
	storebasePath = "./base"
	cstore := NewContextStore(storebasePath)
	defer cleanupstore()

	_, err := cstore.GetContextInfo(testcontextID)
	if err == nil {
		t.Errorf("No error returned for non-existent context")
		t.SkipNow()
	}

	testdata := &testdatastruct{data: 10}

	if cerr := cstore.StoreContext(testcontextID, testdata); cerr != nil {
		t.Errorf("Cannot store data %s ", cerr.Error())
	}

	data, err := cstore.GetContextInfo(testcontextID)
	if err != nil {
		t.Errorf("Unable to get contextinfo %s", err.Error())
		t.SkipNow()
	} else {
		marshaldata, _ := json.Marshal(testdata)
		if !bytes.Equal(data.([]byte), marshaldata) {
			t.Errorf("Data recovered does not match written data")
			t.SkipNow()
		}
	}
}

func TestRemoveContext(t *testing.T) {
	storebasePath = "./base"
	cstore := NewContextStore(storebasePath)
	//defer cleanupstore()

	err := cstore.RemoveContext(testcontextID)
	if err == nil {
		t.Errorf("No Error returned for non-existent context")
		t.SkipNow()
	}
	testdata := &testdatastruct{data: 10}
	if cerr := cstore.StoreContext(testcontextID, testdata); cerr != nil {
		t.Errorf("Cannot store data %s ", cerr.Error())
	}
	if err = cstore.RemoveContext(testcontextID); err != nil {
		t.Errorf("Failed to remove context from store %s", err.Error())
		t.SkipNow()
	} else {
		_, staterr := os.Stat(storebasePath + testcontextID)
		if staterr == nil {
			t.Errorf("Failed to remove context %s", staterr.Error())
			t.SkipNow()
		}
	}
}

func TestWalkStore(t *testing.T) {
	storebasePath = "./base"
	cstore := NewContextStore(storebasePath)
	defer cleanupstore()
	testdata := &testdatastruct{data: 10}
	contextIDList := []string{"/test1", "/test2", "/test3"}

	for _, contextID := range contextIDList {
		if err := cstore.StoreContext(contextID, testdata); err != nil {
			t.Errorf("Cannot store data %s ", err.Error())
		}
	}
	contextchan, _ := cstore.WalkStore()
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
