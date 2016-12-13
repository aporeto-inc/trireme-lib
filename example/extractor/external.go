package main

import (
	"encoding/json"
	"fmt"
	"os"

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
	os.Stdout.Write(jsonResult)
}

func exampleExternalDockerMetadataExtractor(info *types.ContainerJSON) (*policy.PURuntime, error) {

	runtimeInfo := policy.NewPURuntime()

	tags := policy.TagsMap{}
	tags["image"] = info.Config.Image
	tags["name"] = info.Name

	for k, v := range info.Config.Labels {
		tags[k] = v
	}

	ipa := map[string]string{}
	ipa["bridge"] = info.NetworkSettings.IPAddress

	runtimeInfo.SetName(info.Name)
	runtimeInfo.SetPid(info.State.Pid)
	runtimeInfo.SetIPAddresses(ipa)
	runtimeInfo.SetTags(tags)

	return runtimeInfo, nil
}
