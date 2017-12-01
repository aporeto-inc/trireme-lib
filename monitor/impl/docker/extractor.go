package dockermonitor

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/docker/docker/api/types"
)

// defaultMetadataExtractor is the metadata extractor of the agent
func defaultMetadataExtractor(info *types.ContainerJSON) (*policy.PURuntime, error) {

	return policy.NewPURuntime(info.Name, info.State.Pid, "", tags, ipa, constants.ContainerPU, nil), nil
}

// NewExternalExtractor returns a new bash metadata extractor for Docker that will call
// the executable given in parameter and will generate a Policy Runtime as standard output
// The format of Input/Output of the executable are in standard JSON.
func NewExternalExtractor(filePath string) (MetadataExtractor, error) {

	if filePath == "" {
		return nil, fmt.Errorf("file argument is empty in NewBashExtractor")
	}

	path, err := exec.LookPath(filePath)
	if err != nil {
		return nil, fmt.Errorf("Exec file was not found at filePath %s: %s", filePath, err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("Exec file was not found at filePath %s: %s", filePath, err)
	}

	// Generate a new function
	externalExtractor := func(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {

		dockerInfoJSON, err := json.Marshal(dockerInfo)
		if err != nil {
			return nil, fmt.Errorf("Error marshaling dockerInfo: %s", err)
		}

		cmd := exec.Command(path, string(dockerInfoJSON))
		jsonResult, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("Error running bash extractor: %s", err)
		}

		var m policy.PURuntime
		err = json.Unmarshal(jsonResult, &m)
		if err != nil {
			return nil, fmt.Errorf("Error Unmarshaling return from bash extractor: %s", err)
		}

		return &m, nil
	}

	return externalExtractor, nil
}
