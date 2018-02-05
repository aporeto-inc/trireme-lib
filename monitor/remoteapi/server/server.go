package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme-lib/monitor/registerer"
	"github.com/shirou/gopsutil/process"

	"github.com/aporeto-inc/trireme-lib/common"
)

// EventServer is a new event server
type EventServer struct {
	Socket     string
	server     *http.Server
	registerer registerer.Registerer
}

// NewEventServer creates a new event server
func NewEventServer(address string, registerer registerer.Registerer) *EventServer {
	return &EventServer{
		Socket:     address,
		registerer: registerer,
	}
}

// ServeHTTP is called for every request.
func (e *EventServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.create(w, r)
}

// Run runs the server. The server will run in the background. It will
// gracefully die with the provided context.
func (e *EventServer) Run(ctx context.Context) error {

	// Create the handler
	handler := &EventServer{}
	e.server = &http.Server{
		Handler: handler,
	}

	// Start a custom listener
	addr, _ := net.ResolveUnixAddr("unix", e.Socket)
	nl, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("Unable to start API server: %s", err)
	}
	listener := &UIDListener{nl}

	// Start serving HTTP requests in the background
	go e.server.Serve(listener)

	// Listen for context cancellation to close the socket.
	go func() {
		<-ctx.Done()
		nl.Close()
	}()

	return nil
}

// create is the main hadler that process and validates the events
// before calling the actual monitor handlers to process the event.
func (e *EventServer) create(w http.ResponseWriter, r *http.Request) {
	event := &common.EventInfo{}
	if err := json.NewDecoder(r.Body).Decode(event); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := validateTypes(event); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
	}

	if err := validateUser(r, event); err != nil {
		http.Error(w, fmt.Sprintf("invalid-request"), http.StatusForbidden)
		return
	}

	if err := validateEvent(event); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %s", err), http.StatusBadRequest)
	}

	if err := e.processEvent(r.Context(), event); err != nil {
		http.Error(w, "Cannot handle request", http.StatusInternalServerError)
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

	if err := f(ctx, eventInfo); err != nil {
		return err
	}

	return nil
}

// validateUser validates that the originating user is not sending a request
// for a process that they don't own. Root users are allowed to send
// any event.
func validateUser(r *http.Request, event *common.EventInfo) error {

	// Find the calling user.
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) != 3 {
		return fmt.Errorf("Invalid user context")
	}

	// Accept all requests from root users
	if parts[0] == "0" && parts[1] == "0" {
		return nil
	}

	// The target process must be valid.
	p, err := process.NewProcess(event.PID)
	if err != nil {
		return fmt.Errorf("Process not found")
	}

	// The UID of the calling process must match the UID of the target process.
	uids, err := p.Uids()
	if err != nil {
		return fmt.Errorf("Unknown user ID")
	}

	match := false
	for _, uid := range uids {
		if strconv.Itoa(int(uid)) == parts[1] {
			match = true
		}
	}

	if !match {
		return fmt.Errorf("Invalid user - no access to this process")
	}

	return nil
}

// validateTypes validates the various types and prevents any bad strings.
func validateTypes(event *common.EventInfo) error {

	regexStrings := regexp.MustCompile("^[a-zA-Z0-9_:.$%]{0,64}$")
	regexNS := regexp.MustCompile("^[a-zA-Z0-9/]{0,128}$")
	regexCgroup := regexp.MustCompile("^/trireme/(uid/){0,1}[a-zA-Z0-9_:.$%]{1,64}$")

	if _, ok := common.EventMap[event.EventType]; !ok {
		return fmt.Errorf("invalid event: %s", string(event.EventType))
	}

	if event.PUType > common.TransientPU {
		return fmt.Errorf("invalid pu type %v", event.PUType)
	}

	if !regexStrings.Match([]byte(event.Name)) {
		return fmt.Errorf("Name is not of the right format")
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
				if event.Name == "" || event.Name == "default" {
					return fmt.Errorf("Service name must be provided and must not be default")
				}
				event.PUID = event.Name
			} else {
				event.PUID = "host"
			}
		} else {
			if event.PUID == "" {
				event.PUID = strconv.Itoa(int(event.PID))
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
