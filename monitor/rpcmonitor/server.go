package rpcmonitor

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/eventinfo"
	"github.com/aporeto-inc/trireme-lib/monitor/processor"
)

// Server represents the Monitor RPC Server implementation
type Server struct {
	handlers map[constants.PUType]map[monitor.Event]RPCEventHandler
	root     bool
}

// HandleEvent Gets called when clients generate events.
func (s *Server) HandleEvent(eventInfo *eventinfo.EventInfo, result *RPCResponse) error {

	if err := validateEvent(eventInfo); err != nil {
		return err
	}

	if eventInfo.HostService && !s.root {
		return fmt.Errorf("Operation Requires Root Access")
	}

	strtokens := eventInfo.PUID[strings.LastIndex(eventInfo.PUID, "/")+1:]
	if _, ferr := os.Stat("/var/run/trireme/linux/" + strtokens); os.IsNotExist(ferr) && eventInfo.EventType != monitor.EventCreate && eventInfo.EventType != monitor.EventStart {
		eventInfo.PUType = constants.UIDLoginPU
	}
	if _, ok := s.handlers[eventInfo.PUType]; ok {
		f, present := s.handlers[eventInfo.PUType][eventInfo.EventType]
		if present {
			if err := f(eventInfo); err != nil {
				result.Error = err.Error()
				return err
			}
			return nil
		}
	}

	err := fmt.Errorf("No handler found for the event")
	result.Error = err.Error()
	return err

}

// addHandler adds a hadler for a given PU and monitor event
func (s *Server) addHandler(puType constants.PUType, event monitor.Event, handler RPCEventHandler) {
	s.handlers[puType][event] = handler
}

// ReSync handles a server resync
func (s *Server) reSync() error {

	for _, h := range s.handlers {
		if err := h[monitor.EventResync](nil); err != nil {
			return err
		}
	}

	return nil
}

// RegisterProcessor registers an event processor for a given PUTYpe. Only one
// processor is allowed for a given PU Type.
func (s *Server) RegisterProcessor(puType constants.PUType, p processor.EventProcessor) error {

	if _, ok := s.handlers[puType]; ok {
		return fmt.Errorf("Processor already registered for this PU type %d ", puType)
	}

	s.handlers[puType] = map[monitor.Event]RPCEventHandler{}

	s.addHandler(puType, monitor.EventStart, p.Start)
	s.addHandler(puType, monitor.EventStop, p.Stop)
	s.addHandler(puType, monitor.EventCreate, p.Create)
	s.addHandler(puType, monitor.EventDestroy, p.Destroy)
	s.addHandler(puType, monitor.EventPause, p.Pause)
	s.addHandler(puType, monitor.EventResync, p.ReSync)

	return nil
}

func validateEvent(event *eventinfo.EventInfo) error {

	if event.EventType == monitor.EventCreate || event.EventType == monitor.EventStart {
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
			if event.PUType != constants.UIDLoginPU || event.PUID == "" {
				event.PUID = event.PID
			}
		}
	}

	if event.EventType == monitor.EventStop || event.EventType == monitor.EventDestroy {
		regStop := regexp.MustCompile("^/trireme/[a-zA-Z0-9_].{0,11}$")
		if event.Cgroup != "" && !regStop.Match([]byte(event.Cgroup)) {
			return fmt.Errorf("Cgroup is not of the right format")
		}
	}

	return nil
}
