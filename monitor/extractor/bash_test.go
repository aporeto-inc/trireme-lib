package extractor

import (
	"bufio"
	"fmt"
	"os"

	"testing"
)

func TestCreate(t *testing.T) {
	// Test for Empty file.
	_, err := NewBashExtractor("")
	if err == nil {
		t.Errorf("Expected Error, but got none")
	}

	// Test for NonExistent file.
	_, err = NewBashExtractor("/tmp/abcde.test")
	if err == nil {
		t.Errorf("Expected Error, but got none")
	}
}

const testfile = `#!/bin/sh
echo '{"Pid":16823,"Name":"/stoic_snyder","IPAddresses":{"bridge":"172.17.0.2"},"Tags":{"image":"nginx","name":"/stoic_snyder"}}'
`

func createFileTest(destination string) {
	fileHandle, _ := os.Create(destination)
	writer := bufio.NewWriter(fileHandle)
	fmt.Fprintln(writer, testfile)
	writer.Flush()
}

func TestReturnedFunc(t *testing.T) {
	createFileTest("/tmp/test.sh")
	function, err := NewBashExtractor("/tmp/test.sh")
	if err != nil {
		t.Errorf("Didn't expect error but received %s", err)
	}
	PUruntime, err := function(nil)
	if err != nil {

	}
	ip, _ := PUruntime.DefaultIPAddress()
	if ip != "172.17.0.2" {
		t.Errorf("Unmarshalled information %s didn't correspond to Mock data %s", ip, "172.17.0.2")
	}

}
