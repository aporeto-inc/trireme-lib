package extractors

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/monitor/constants"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cgnetcls"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portspec"
)

// A DockerMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// docker ContainerJSON.
type DockerMetadataExtractor func(*types.ContainerJSON) (*policy.PURuntime, error)

// DefaultMetadataExtractor is the default metadata extractor for Docker
func DefaultMetadataExtractor(info *types.ContainerJSON) (*policy.PURuntime, error) {

	// trigger new build
	tags := policy.NewTagStore()
	tags.AppendKeyValue("@app:image", info.Config.Image)
	tags.AppendKeyValue("@app:extractor", "docker")
	tags.AppendKeyValue("@app:docker:name", info.Name)

	for k, v := range info.Config.Labels {
		if len(strings.TrimSpace(k)) == 0 {
			continue
		}
		value := v
		if len(v) == 0 {
			value = "<empty>"
		}
		if !strings.HasPrefix(k, constants.UserLabelPrefix) {
			tags.AppendKeyValue(constants.UserLabelPrefix+k, value)
		} else {
			tags.AppendKeyValue(k, value)
		}
	}

	ipa := policy.ExtendedMap{
		"bridge": info.NetworkSettings.IPAddress,
	}

	if info.HostConfig.NetworkMode == constants.DockerHostMode {
		return policy.NewPURuntime(info.Name, info.State.Pid, "", tags, ipa, common.LinuxProcessPU, policy.None, hostModeOptions(info)), nil
	}

	return policy.NewPURuntime(info.Name, info.State.Pid, "", tags, ipa, common.ContainerPU, policy.None, nil), nil
}

// hostModeOptions creates the default options for a host-mode container. This is done
// based on the policy and the metadata extractor logic and can very by implementation
func hostModeOptions(dockerInfo *types.ContainerJSON) *policy.OptionsType {

	options := policy.OptionsType{
		CgroupName: strconv.Itoa(dockerInfo.State.Pid),
		CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
		AutoPort:   true,
	}

	for p := range dockerInfo.Config.ExposedPorts {
		if p.Proto() == "tcp" {
			s, err := portspec.NewPortSpecFromString(p.Port(), nil)
			if err != nil {
				continue
			}

			options.Services = append(options.Services, common.Service{
				Protocol: uint8(6),
				Ports:    s,
			})
		}
	}

	return &options
}

// NewExternalExtractor returns a new bash metadata extractor for Docker that will call
// the executable given in parameter and will generate a Policy Runtime as standard output
// The format of Input/Output of the executable are in standard JSON.
func NewExternalExtractor(filePath string) (DockerMetadataExtractor, error) {

	if filePath == "" {
		return nil, errors.New("file argument is empty in bash extractor")
	}

	path, err := exec.LookPath(filePath)
	if err != nil {
		return nil, fmt.Errorf("exec file not found %s: %s", filePath, err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("exec file not found %s: %s", filePath, err)
	}

	// Generate a new function
	externalExtractor := func(dockerInfo *types.ContainerJSON) (*policy.PURuntime, error) {

		dockerInfoJSON, err := json.Marshal(dockerInfo)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal docker info: %s", err)
		}

		cmd := exec.Command(path, string(dockerInfoJSON))
		jsonResult, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("unable to run bash extractor: %s", err)
		}

		var m policy.PURuntime
		err = json.Unmarshal(jsonResult, &m)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal data from bash extractor: %s", err)
		}

		return &m, nil
	}

	return externalExtractor, nil
}
