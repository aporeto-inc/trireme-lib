// +build !windows

package extractors

import (
	"bufio"
	"fmt"
	"os"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"go.aporeto.io/trireme-lib/monitor/constants"
)

func TestDefaultMetadataExtractor(t *testing.T) {
	info := &types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			Name:  "name",
			State: &types.ContainerState{},
			HostConfig: &container.HostConfig{
				NetworkMode: constants.DockerHostMode,
			},
		},
		NetworkSettings: &types.NetworkSettings{
			DefaultNetworkSettings: types.DefaultNetworkSettings{
				IPAddress: "10.0.0.1",
			},
		},
		Config: &container.Config{
			Image: "image",
			Labels: map[string]string{
				"   ":            "remove me",
				"empty-label":    "",
				"standard-label": "one",
			},
		},
	}

	pu, err := DefaultMetadataExtractor(info)
	if err != nil {
		t.Error(err)
	}
	var foundEmptyTag bool
	for _, tag := range pu.Tags().Tags {
		if tag == "@usr:empty-label=<empty>" {
			foundEmptyTag = true
			break
		}
	}
	if !foundEmptyTag {
		t.Error("empty tag not found")
	}
}

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
	_, err = function(nil)
	if err != nil {
		t.Errorf("Failed to create extractor")
	}
}
