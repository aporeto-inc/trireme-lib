package contextstore

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	os.RemoveAll(storebasePath)
}
func TestStoreContext(t *testing.T) {

	cstore := NewContextStore()
	defer cleanupstore()
	testdata := &testdatastruct{data: 10}
	marshaldata, _ := json.Marshal(testdata)
	err := cstore.StoreContext(testcontextID, testdata)
	if err != nil {
		t.Errorf("Failed to store context data %s", err.Error())
		t.SkipNow()
	} else {
		readdata, _ := ioutil.ReadFile(storebasePath + testcontextID + eventInfoFile)
		if strings.TrimSpace(string(readdata)) != string(marshaldata) {
			t.Errorf("Data corrupted in store")
			t.SkipNow()
		}
	}

}
func TestDestroyStore(t *testing.T) {
	cstore := NewContextStore()
	defer cleanupstore()

	os.RemoveAll(storebasePath)
	if err := cstore.DestroyStore(); err == nil {
		t.Errorf("No Error returned for uninited store")
		t.SkipNow()
	}
	//Reinit store
	cstore = NewContextStore()
	testdata := &testdatastruct{data: 10}
	cstore.StoreContext(testcontextID, testdata)
	if err := cstore.DestroyStore(); err != nil {
		t.Errorf("Unable to destroy contextstore %s", err.Error())
		t.SkipNow()
	}

}
func TestGetContextInfo(t *testing.T) {
	cstore := NewContextStore()
	defer cleanupstore()

	data, err := cstore.GetContextInfo(testcontextID)
	if err == nil {
		t.Errorf("No error returned for non-existent context")
		t.SkipNow()
	}
	testdata := &testdatastruct{data: 10}

	cstore.StoreContext(testcontextID, testdata)
	data, err = cstore.GetContextInfo(testcontextID)
	if err != nil {
		t.Errorf("Unable to get contextinfo %s", err.Error())
		t.SkipNow()
	} else {
		marshaldata, _ := json.Marshal(testdata)
		if bytes.Compare(data.([]byte), marshaldata) != 0 {
			t.Errorf("Data recovered does not match written data")
			t.SkipNow()
		}
	}

}
func TestRemoveContext(t *testing.T) {
	cstore := NewContextStore()
	//defer cleanupstore()

	err := cstore.RemoveContext(testcontextID)
	if err == nil {
		t.Errorf("No Error returned for non-existent context")
		t.SkipNow()
	}
	testdata := &testdatastruct{data: 10}
	cstore.StoreContext(testcontextID, testdata)
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
	cstore := NewContextStore()
	//defer cleanupstore()
	testdata := &testdatastruct{data: 10}
	contextIDList := []string{"/test1", "/test2", "/test3"}

	for _, contextID := range contextIDList {
		cstore.StoreContext(contextID, testdata)
	}
	contextchan, _ := cstore.WalkStore()
	index := 0
	for {
		c := <-contextchan
		fmt.Println(c)
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
