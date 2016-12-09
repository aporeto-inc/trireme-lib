package extractor

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/docker/docker/api/types"
)

// NewBashExtractor returns a new bash metadata extractor for Docker that will call
// the executable given in parameter and will generate a Policy Runtime as standard output
// The format of Input/Output of the executable are in standard JSON.
func NewBashExtractor(filePath string) (monitor.DockerMetadataExtractor, error) {
	if filePath == "" {
		return nil, fmt.Errorf("file argument is empty in NewBashExtractor")
	}

	path, err := exec.LookPath(filePath)
	if err != nil {
		return nil, fmt.Errorf("Exec file was not found at filePath %s: %s", filePath, err)
	}

	// Generate a new function
	bashExtractor := func(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {
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

	return bashExtractor, nil
}
