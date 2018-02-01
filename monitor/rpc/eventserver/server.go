package eventserver

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/registerer"
)

const (
	maxEventNameLength = 64
)

// Server represents the Monitor RPC Server implementation
type Server struct {
	root       bool
	registerer registerer.Registerer
}

// New provides a new event server. This server will be responsible for listening
// events over the incoming RPC channel
func New(root bool) (Processor, registerer.Registerer) {

	es := &Server{
		root:       root,
		registerer: registerer.New(),
	}
	return es, es.registerer
}

// HandleEvent Gets called when clients generate common.
func (s *Server) HandleEvent(eventInfo *common.EventInfo, result *common.EventResponse) (err error) {

	if err = validateEvent(eventInfo); err != nil {
		return err
	}

	if eventInfo.HostService && !s.root {
		return fmt.Errorf("Operation Requires Root Access")
	}

	lastSlash := strings.LastIndex(eventInfo.PUID, "/") + 1
	if lastSlash > len(eventInfo.PUID) {
		return fmt.Errorf("Invalid PUID %v", eventInfo.PUID)
	}

	puID := eventInfo.PUID[lastSlash:]
	if _, err = os.Stat("/var/run/trireme/linux/" + puID); os.IsNotExist(err) &&
		eventInfo.EventType != common.EventCreate &&
		eventInfo.EventType != common.EventStart &&
		!eventInfo.HostService {
		eventInfo.PUType = common.UIDLoginPU
	}

	f, err := s.registerer.GetHandler(eventInfo.PUType, eventInfo.EventType)
	if err != nil {
		err = fmt.Errorf("Handler not found: %s", err.Error())
		result.Error = err.Error()
		return err
	}

	if err := f(eventInfo); err != nil {
		result.Error = err.Error()
		return err
	}

	return nil
}

func validateEvent(event *common.EventInfo) error {

	if event.EventType == common.EventCreate || event.EventType == common.EventStart {
		if len(event.Name) > maxEventNameLength {
			return fmt.Errorf("Invalid Event Name - Must not be nil or greater than 64 characters")
		}

		if event.PID == "" {
			return fmt.Errorf("PID cannot be empty")
		}

		pid, err := strconv.Atoi(event.PID)
		if err != nil || pid < 0 {
			return fmt.Errorf("Invalid PID - Must be a positive number")
		}

		if event.HostService {
			if event.NetworkOnlyTraffic {
				if event.Name == "" || event.Name == "default" {
					return fmt.Errorf("Service name must be provided and must be not be default")
				}
				event.PUID = event.Name
			} else {
				event.Name = "DefaultServer"
				event.PUID = "default"
			}

		} else {
			if event.PUType != common.UIDLoginPU || event.PUID == "" {
				event.PUID = event.PID
			}
		}
	}

	if event.EventType == common.EventStop || event.EventType == common.EventDestroy {
		regStop := regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$")
		if event.Cgroup != "" && !regStop.Match([]byte(event.Cgroup)) {
			return fmt.Errorf("Cgroup is not of the right format")
		}
	}

	return nil
}
