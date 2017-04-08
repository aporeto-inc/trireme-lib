package cliextractor

import (
	"bufio"
	"fmt"
	"os"

	"testing"
)

func TestCreate(t *testing.T) {
	// Test for Empty file.
	_, err := NewExternalExtractor("")
	if err == nil {
		t.Errorf("Expected Error, but got none")
	}

	// Test for NonExistent file.
	_, err = NewExternalExtractor("/tmp/abcde.test")
	if err == nil {
		t.Errorf("Expected Error, but got none")
	}
}

const testfile = `#!/bin/sh
echo '{"Pid":16823,"Name":"/stoic_snyder","IPAddresses":{"bridge":"172.17.0.2"},"Tags":{"image":"nginx","name":"/stoic_snyder"}}'
`

func createFileTest(destination string) error {
	fileHandle, err := os.Create(destination)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(fileHandle)
	fmt.Fprintln(writer, testfile)
	writer.Flush() // nolint : errcheck
	return nil
}

func TestReturnedFunc(t *testing.T) {
	if err := createFileTest("/tmp/test.sh"); err != nil {
		t.Skipf("Skip test because no support for writing files to /tmp")
	}
	function, err := NewExternalExtractor("/tmp/test.sh")
	if err != nil {
		t.Skipf("Skip test because no support for writing files to /tmp")
	}
	PUruntime, err := function(nil)
	if err != nil {
		t.Errorf("Failed to create extractor")
	}
	ip, _ := PUruntime.DefaultIPAddress()
	if ip != "172.17.0.2" {
		t.Errorf("Unmarshalled information %s didn't correspond to Mock data %s", ip, "172.17.0.2")
	}

}
