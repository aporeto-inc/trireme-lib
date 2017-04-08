package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/docker/docker/api/types"
)

/*

Standard example of an external docker metadata extractor.
INPUT as arg[1]: The docker Container JSON with all the related information as defined in github.com/docker/docker/api/types
OUTPUT on STDPUT: The JSON representation (marshalled) of the PURuntime as defined in github.com/aporeto-inc/trireme/policy

*/

func main() {
	jsonFromDocker := os.Args[1]
	var m types.ContainerJSON

	// Getting the Docker information out of the JSON format in the STDIN.
	err := json.Unmarshal([]byte(jsonFromDocker), &m)
	if err != nil {
		fmt.Printf("Received error unmarshal: %s \n", err)
	}

	// Use this local function to fill-in the Extractor.
	extractorResult, err := exampleExternalDockerMetadataExtractor(&m)
	if err != nil {
		fmt.Printf("Received error extractor: %s \n", err)
	}

	// Transfer the resultin PURuntime in JSON format.
	jsonResult, err := json.Marshal(extractorResult)
	if err != nil {
		fmt.Printf("Received error marshal: %s \n", err)
	}

	// Write it out on STDOUT.
	if _, err = os.Stdout.Write(jsonResult); err != nil {
		fmt.Printf("Failed to write JSON to stdout")
	}
}

func exampleExternalDockerMetadataExtractor(info *types.ContainerJSON) (*policy.PURuntime, error) {

	tagsMap := policy.NewTagsMap(map[string]string{
		"image": info.Config.Image,
		"name":  info.Name,
	})
	for k, v := range info.Config.Labels {
		tagsMap.Add(k, v)
	}

	ipa := policy.NewIPMap(map[string]string{
		"bridge": info.NetworkSettings.IPAddress,
	})
	return policy.NewPURuntime(info.Name, info.State.Pid, tagsMap, ipa, constants.ContainerPU, nil), nil
}
