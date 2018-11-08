package systemdutil

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"syscall"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/monitor/remoteapi/client"
	"go.aporeto.io/trireme-lib/utils/portspec"
)

var stderrlogger *log.Logger

func init() {
	stderrlogger = log.New(os.Stderr, "", 0)
}

// ExecuteCommandFromArguments processes the command from the arguments
func ExecuteCommandFromArguments(arguments map[string]interface{}) error {

	p := NewRequestProcessor()

	c, err := p.ParseCommand(arguments)
	if err != nil {
		return err
	}

	return p.ExecuteRequest(c)
}

// RequestType is the type of the request
type RequestType int

const (
	// CreateRequest requests a create event
	CreateRequest RequestType = iota
	// DeleteCgroupRequest requests deletion based on the cgroup - issued by the kernel
	DeleteCgroupRequest
	// DeleteServiceRequest requests deletion by the service ID
	DeleteServiceRequest
)

// CLIRequest captures all CLI parameters
type CLIRequest struct {
	// Request is the type of the request
	Request RequestType
	// Cgroup is only provided for delete cgroup requests
	Cgroup string
	// Executable is the path to the executable
	Executable string
	// Parameters are the parameters of the executable
	Parameters []string
	// Labels are the user labels attached to the request
	Labels []string
	// ServiceName is a user defined service name
	ServiceName string
	// Services are the user defined services (protocol, port)
	Services []common.Service
	// HostPolicy indicates that this is a host policy
	HostPolicy bool
	// NetworkOnly indicates that the request is only for traffic coming from the network
	NetworkOnly bool
	// UIDPOlicy indicates that the request is for a UID policy
	UIDPolicy bool
	// AutoPort indicates that auto port feature is enabled for the PU
	AutoPort bool
}

// RequestProcessor is an instance of the processor
type RequestProcessor struct {
	address string
}

// NewRequestProcessor creates a default request processor
func NewRequestProcessor() *RequestProcessor {
	return &RequestProcessor{
		address: common.TriremeSocket,
	}
}

// NewCustomRequestProcessor creates a new request processor
func NewCustomRequestProcessor(address string) *RequestProcessor {
	r := NewRequestProcessor()

	if address != "" {
		r.address = address
	}

	return r
}

// Generic command line arguments
// Assumes a command like that:
// usage = `Trireme Client Command
//
// Usage: enforcerd -h | --help
// 		 trireme -v | --version
// 		 trireme run
// 			[--service-name=<sname>]
// 			[[--ports=<ports>]...]
// 			[[--label=<keyvalue>]...]
// 			[--networkonly]
// 			[--hostpolicy]
//          [--uidpolicy]
// 			[<command> [--] [<params>...]]
// 		 trireme rm
//          [--service-name=<sname>]
// 			[--hostpolicy]
//          [--uidpolicy]
// 		 trireme <cgroup>
//
// Run Client Options:
// 	--service-name=<sname>              Service name for the executed command [default ].
// 	--ports=<ports>                     Ports that the executed service is listening to [default ].
// 	--label=<keyvalue>                  Label (key/value pair) attached to the service [default ].
// 	--networkonly                       Control traffic from the network only and not from applications [default false].
// 	--hostpolicy                        Default control of the base namespace [default false].
// 	--uidpolicy                         Default control of the base namespace [default false].
//
// `

// ParseCommand parses a command based on the above specification
// This is a helper function for CLIs like in Trireme Example.
// Proper use is through the CLIRequest structure
func (r *RequestProcessor) ParseCommand(arguments map[string]interface{}) (*CLIRequest, error) {

	c := &CLIRequest{}

	// First parse a command that only provides the cgroup
	// The kernel will only send us a command with one argument
	if value, ok := arguments["<cgroup>"]; ok && value != nil {
		c.Cgroup = value.(string)
		c.Request = DeleteCgroupRequest
		return c, nil
	}

	if value, ok := arguments["--service-name"]; ok && value != nil {
		c.ServiceName = value.(string)
	}

	if value, ok := arguments["--hostpolicy"]; ok && value != nil {
		c.HostPolicy = value.(bool)
	}

	if value, ok := arguments["--uidpolicy"]; ok && value != nil {
		c.UIDPolicy = value.(bool)
	}

	// If the command is remove use hostpolicy and service-id
	if arguments["rm"].(bool) {
		c.Request = DeleteServiceRequest
		return c, nil
	}

	// Process the rest of the arguments of the run command
	if value, ok := arguments["run"]; !ok || value == nil {
		return nil, errors.New("invalid command")
	}

	// This is a create request - proceed
	c.Request = CreateRequest

	if value, ok := arguments["<command>"]; ok && value != nil {
		c.Executable = value.(string)
	}

	if value, ok := arguments["--label"]; ok && value != nil {
		c.Labels = value.([]string)
	}

	if value, ok := arguments["<params>"]; ok && value != nil {
		c.Parameters = value.([]string)
	}

	if value, ok := arguments["--ports"]; ok && value != nil {
		services, err := ParseServices(value.([]string))
		if err != nil {
			return nil, err
		}
		c.Services = services
	}

	if value, ok := arguments["--autoport"]; ok && value != nil {
		c.AutoPort = value.(bool)
	}

	if value, ok := arguments["--networkonly"]; ok && value != nil {
		c.NetworkOnly = value.(bool)
	}

	return c, nil
}

// CreateAndRun creates a processing unit
func (r *RequestProcessor) CreateAndRun(c *CLIRequest) error {
	var err error

	// If its not hostPolicy and the command doesn't exist we return an error
	if !c.HostPolicy {
		if c.Executable == "" {
			return errors.New("command must be provided")
		}
		if !path.IsAbs(c.Executable) {
			c.Executable, err = exec.LookPath(c.Executable)
			if err != nil {
				return err
			}
		}
		if c.ServiceName == "" {
			c.ServiceName = c.Executable
		}
	}

	// This is added since the release_notification comes in this format
	// Easier to massage it while creation rather than change at the receiving end depending on event
	request := &common.EventInfo{
		PUType:             common.LinuxProcessPU,
		Name:               c.ServiceName,
		Tags:               c.Labels,
		PID:                int32(os.Getpid()),
		EventType:          common.EventStart,
		Services:           c.Services,
		NetworkOnlyTraffic: c.NetworkOnly,
		HostService:        c.HostPolicy,
		AutoPort:           c.AutoPort,
	}

	if err := sendRequest(r.address, request); err != nil {
		return err
	}

	if c.HostPolicy {
		return nil
	}

	env := os.Environ()
	env = append(env, "APORETO_WRAP=1")
	return syscall.Exec(c.Executable, append([]string{c.Executable}, c.Parameters...), env)
}

// DeleteService will issue a delete command
func (r *RequestProcessor) DeleteService(c *CLIRequest) error {

	request := &common.EventInfo{
		PUType:      common.LinuxProcessPU,
		PUID:        c.ServiceName,
		EventType:   common.EventStop,
		HostService: c.HostPolicy,
	}

	if c.UIDPolicy {
		request.PUType = common.UIDLoginPU
	}

	// Send Stop request
	if err := sendRequest(r.address, request); err != nil {
		return err
	}

	// Send destroy request
	request.EventType = common.EventDestroy

	return sendRequest(r.address, request)
}

// DeleteCgroup will issue a delete command based on the cgroup
// This is used mainly by the cleaner.
func (r *RequestProcessor) DeleteCgroup(c *CLIRequest) error {
	regexCgroup := regexp.MustCompile(`^/trireme/[a-zA-Z0-9_\-:.$%]{1,64}$`)
	regexUser := regexp.MustCompile(`^/trireme_uid/[a-zA-Z0-9_\-]{1,32}(/[0-9]{1,32}){0,1}$`)

	if !regexCgroup.Match([]byte(c.Cgroup)) && !regexUser.Match([]byte(c.Cgroup)) {
		return fmt.Errorf("invalid cgroup: %s", c.Cgroup)
	}

	var eventPUID string
	var eventType common.PUType

	if strings.HasPrefix(c.Cgroup, common.TriremeUIDCgroupPath) {
		eventType = common.UIDLoginPU
		eventPUID = c.Cgroup[len(common.TriremeUIDCgroupPath):]
	} else if strings.HasPrefix(c.Cgroup, common.TriremeCgroupPath) {
		eventType = common.LinuxProcessPU
		eventPUID = c.Cgroup[len(common.TriremeCgroupPath):]
	} else {
		// Not our Cgroup
		return nil
	}

	request := &common.EventInfo{
		PUType:    eventType,
		PUID:      eventPUID,
		EventType: common.EventStop,
	}

	// Send Stop request
	if err := sendRequest(r.address, request); err != nil {
		return err
	}

	// Send destroy request
	request.EventType = common.EventDestroy

	return sendRequest(r.address, request)
}

// ExecuteRequest executes the command with an RPC request
func (r *RequestProcessor) ExecuteRequest(c *CLIRequest) error {

	switch c.Request {
	case CreateRequest:
		return r.CreateAndRun(c)
	case DeleteCgroupRequest:
		return r.DeleteCgroup(c)
	case DeleteServiceRequest:
		return r.DeleteService(c)
	default:
		return fmt.Errorf("unknown request: %d", c.Request)
	}
}

// sendRequest sends an RPC request to the provided address
func sendRequest(address string, event *common.EventInfo) error {

	client, err := client.NewClient(address)
	if err != nil {
		return err
	}

	return client.SendRequest(event)
}

// ParseServices parses strings with the services and returns them in an
// validated slice
func ParseServices(ports []string) ([]common.Service, error) {

	// If no ports are provided, we add the default 0 port
	if len(ports) == 0 {
		ports = append(ports, "0")
	}

	// Parse the ports and create the services. Cleanup any bad ports
	services := []common.Service{}
	protocol := packet.IPProtocolTCP

	for _, p := range ports {
		// check for port string of form port#/udp eg 8085/udp
		portProtocolPair := strings.Split(p, "/")
		if len(portProtocolPair) > 2 || len(portProtocolPair) <= 0 {
			return nil, fmt.Errorf("Invalid port format. Expected format is of form 80 or 8085/udp")
		}

		if len(portProtocolPair) == 2 {
			if portProtocolPair[1] == "tcp" {
				protocol = packet.IPProtocolTCP
			} else if portProtocolPair[1] == "udp" {
				protocol = packet.IPProtocolUDP
			} else {
				return nil, fmt.Errorf("Invalid protocol specified. Only tcp/udp accepted")
			}
		}

		s, err := portspec.NewPortSpecFromString(portProtocolPair[0], nil)
		if err != nil {
			return nil, fmt.Errorf("Invalid port spec: %s ", err)
		}

		services = append(services, common.Service{
			Protocol: uint8(protocol),
			Ports:    s,
		})
	}

	return services, nil
}
