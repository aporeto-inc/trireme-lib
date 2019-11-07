package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/registerer"
	"go.uber.org/zap"
)

// EventServer is a new event server
type EventServer struct {
	socketPath string
	server     *http.Server
	registerer registerer.Registerer
}

// NewEventServer creates a new event server
func NewEventServer(address string, registerer registerer.Registerer) (*EventServer, error) {

	err := cleanupPipe(address)
	if err != nil {
		return nil, err
	}

	return &EventServer{
		socketPath: address,
		registerer: registerer,
	}, nil
}

// ServeHTTP is called for every request.
func (e *EventServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.create(w, r)
}

// Run runs the server. The server will run in the background. It will
// gracefully die with the provided context.
func (e *EventServer) Run(ctx context.Context) error {

	// Create the handler
	e.server = &http.Server{
		Handler: e,
	}

	listener, err := e.makePipe()

	if err != nil {
		return err
	}

	// Start serving HTTP requests in the background
	go e.server.Serve(listener) // nolint

	// Listen for context cancellation to close the socket.
	go func() {
		<-ctx.Done()
		listener.Close() // nolint
	}()

	return nil
}

// create is the main hadler that process and validates the events
// before calling the actual monitor handlers to process the event.
func (e *EventServer) create(w http.ResponseWriter, r *http.Request) {
	event := &common.EventInfo{}
	defer r.Body.Close() // nolint

	if err := json.NewDecoder(r.Body).Decode(event); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := validateTypes(event); err != nil {
		zap.L().Error("Error in validating types", zap.Error(err), zap.Reflect("Event", event))
		http.Error(w, fmt.Sprintf("Invalid request fields: %s", err), http.StatusBadRequest)
		return
	}

	if err := validateUser(r, event); err != nil {
		http.Error(w, fmt.Sprintf("Invalid user to pid mapping found: %s", err), http.StatusForbidden)
		return
	}

	if err := validateEvent(event); err != nil {
		http.Error(w, fmt.Sprintf("Bad request: %s", err), http.StatusBadRequest)
		return
	}

	if err := e.processEvent(r.Context(), event); err != nil {
		zap.L().Error("Error in processing event", zap.Error(err), zap.Reflect("Event", event))
		http.Error(w, fmt.Sprintf("Cannot handle request: %s", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// processEvent processes the event by retrieving the right monitor handler.
func (e *EventServer) processEvent(ctx context.Context, eventInfo *common.EventInfo) (err error) {

	if e.registerer == nil {
		return fmt.Errorf("No registered handlers")
	}

	f, err := e.registerer.GetHandler(eventInfo.PUType, eventInfo.EventType)
	if err != nil {
		return fmt.Errorf("Handler not found: %s", err)
	}

	return f(ctx, eventInfo)
}

// validateTypes validates the various types and prevents any bad strings.
func validateTypes(event *common.EventInfo) error {

	regexStrings := regexp.MustCompile("^[a-zA-Z0-9_:.$%/-]{0,256}$")
	regexNS := regexp.MustCompile("^[a-zA-Z0-9/-]{0,128}$")
	regexCgroup := regexp.MustCompile("^/trireme/(uid/){0,1}[a-zA-Z0-9_:.$%]{1,64}$")

	if _, ok := common.EventMap[event.EventType]; !ok {
		return fmt.Errorf("invalid event: %s", string(event.EventType))
	}

	if event.PUType > common.TransientPU {
		return fmt.Errorf("invalid pu type %v", event.PUType)
	}

	if event.PUType == common.UIDLoginPU {
		if !regexStrings.Match([]byte(event.Name)) {
			return fmt.Errorf("Name is not of the right format")
		}
	}

	if len(event.Cgroup) > 0 && !regexCgroup.Match([]byte(event.Cgroup)) {
		return fmt.Errorf("Invalid cgroup format: %s", event.Cgroup)
	}

	if !regexNS.Match([]byte(event.NS)) {
		return fmt.Errorf("Namespace is not of the right format")
	}

	for k, v := range event.IPs {
		if !regexStrings.Match([]byte(k)) {
			return fmt.Errorf("Invalid IP name: %s", k)
		}

		if ip := net.ParseIP(v); ip == nil {
			return fmt.Errorf("Invalid IP address: %s", v)
		}
	}

	return nil
}

// validateEvent validates that this is reasonable event and
// modifies the default values.
func validateEvent(event *common.EventInfo) error {

	if event.EventType == common.EventCreate || event.EventType == common.EventStart {
		if event.HostService {
			if event.NetworkOnlyTraffic {
				if event.Name == "" {
					return fmt.Errorf("Service name must be provided and must not be default")
				}
			}
		} else {
			if event.PUID == "" {
				event.PUID = strconv.Itoa(int(event.PID))
			}
		}
	}

	if event.EventType == common.EventStop || event.EventType == common.EventDestroy {
		regStop := regexp.MustCompile("^/trireme/[a-zA-Z0-9_]{1,11}$")
		if event.Cgroup != "" && !regStop.Match([]byte(event.Cgroup)) {
			return fmt.Errorf("Cgroup is not of the right format")
		}
	}

	return nil
}
