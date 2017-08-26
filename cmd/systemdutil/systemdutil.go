package systemdutil

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
)

const (
	maxRetries       = 4
	remoteMethodCall = "Server.HandleEvent"
)

// ExecuteCommand executes a command in a cgroup and programs Trireme
// TODO : This method is deprecated and should be removed once there is no code using it.
func ExecuteCommand(arguments map[string]interface{}) error {

	var command string
	if value, ok := arguments["<command>"]; ok && value != nil {
		command = value.(string)
	}

	var cgroup string
	if value, ok := arguments["<cgroup>"]; ok && value != nil {
		cgroup = value.(string)
	}

	var labels []string
	if value, ok := arguments["--label"]; ok && value != nil {
		labels = value.([]string)
	}

	var serviceName string
	if value, ok := arguments["--service-name"]; ok && value != nil {
		serviceName = value.(string)
	}

	var params []string
	if value, ok := arguments["<params>"]; ok && value != nil {
		params = append(params, value.([]string)...)
	}

	var ports []string
	if value, ok := arguments["--ports"]; ok && value != nil {
		ports = value.([]string)
	}

	return ExecuteCommandWithParameters(command, params, cgroup, serviceName, ports, labels)
}

// ExecuteCommandWithParameters executes the command with all the given parameters
func ExecuteCommandWithParameters(command string, params []string, cgroup string, serviceName string, ports []string, tags []string) error {

	var err error

	stderrlogger := log.New(os.Stderr, "", 0)
	if cgroup != "" {
		if err = HandleCgroupStop(cgroup); err != nil {
			err = fmt.Errorf("cannot connect to policy process %s. Resources not deleted", err)
			stderrlogger.Print(err)
			return err
		}

		return nil
	}

	if len(ports) == 0 {
		ports = append(ports, "0")
	}

	if !path.IsAbs(command) {
		command, err = exec.LookPath(command)
		if err != nil {
			return err
		}
	}

	name, metadata, err := createMetadata(serviceName, command, ports, tags)
	if err != nil {
		err = fmt.Errorf("Invalid metadata: %s", err)
		stderrlogger.Print(err)
		return err
	}

	// Make RPC call and only retry if the resource is temporarily unavailable
	numRetries := 0
	client, err := net.Dial("unix", rpcmonitor.DefaultRPCAddress)
	for err != nil {
		numRetries++
		nerr, ok := err.(*net.OpError)

		if numRetries >= maxRetries || !(ok && nerr.Err == syscall.EAGAIN) {
			err = fmt.Errorf("Cannot connect to policy process %s", err)
			stderrlogger.Print(err)
			return err
		}

		time.Sleep(5 * time.Millisecond)
		client, err = net.Dial("unix", rpcmonitor.DefaultRPCAddress)
	}

	//This is added since the release_notification comes in this format
	//Easier to massage it while creation rather than change at the receiving end depending on event
	request := &rpcmonitor.EventInfo{
		PUType:    constants.LinuxProcessPU,
		PUID:      "/" + strconv.Itoa(os.Getpid()),
		Name:      name,
		Tags:      metadata,
		PID:       strconv.Itoa(os.Getpid()),
		EventType: "start",
	}

	response := &rpcmonitor.RPCResponse{}
	rpcClient := jsonrpc.NewClient(client)
	err = rpcClient.Call(remoteMethodCall, request, response)

	if err != nil {
		err = fmt.Errorf("Policy Server call failed %s", err.Error())
		stderrlogger.Print(err)
		return err
	}

	if len(response.Error) > 0 {
		err = fmt.Errorf("Your policy does not allow you to run this command")
		stderrlogger.Print(err)
		return err
	}

	return syscall.Exec(command, append([]string{command}, params...), os.Environ())

}

// createMetadata extracts the relevant metadata
func createMetadata(serviceName string, command string, ports []string, tags []string) (string, map[string]string, error) {

	metadata := map[string]string{}

	for _, tag := range tags {
		keyvalue := strings.SplitN(tag, "=", 2)

		if len(keyvalue) != 2 {
			return "", nil, fmt.Errorf("Metadata should have the form key=value. Found %s instead", tag)
		}

		if keyvalue[0][0] == []byte("$")[0] || keyvalue[0][0] == []byte("@")[0] {
			return "", nil, fmt.Errorf("Metadata cannot start with $ or @")
		}

		if keyvalue[0] == "port" || keyvalue[0] == "execpath" {
			return "", nil, fmt.Errorf("Metadata key cannot be port or execpath ")
		}

		metadata[keyvalue[0]] = keyvalue[1]
	}

	metadata["port"] = strings.Join(ports, ",")
	metadata["execpath"] = command

	name := command
	if serviceName != "" {
		name = serviceName
	}

	return name, metadata, nil
}

// HandleCgroupStop handles the deletion of a cgroup
func HandleCgroupStop(cgroupName string) error {

	client, err := net.Dial("unix", rpcmonitor.DefaultRPCAddress)
	if err != nil {
		return err
	}
	filepath := "/var/run"
	request := &rpcmonitor.EventInfo{
		PUType:    constants.LinuxProcessPU,
		PUID:      cgroupName,
		Name:      cgroupName,
		Tags:      nil,
		PID:       strconv.Itoa(os.Getpid()),
		EventType: monitor.EventStop,
	}

	if _, ferr := os.Stat(filepath + cgroupName); os.IsNotExist(ferr) {
		request.PUType = constants.UIDLoginPU
	}

	response := &rpcmonitor.RPCResponse{}

	rpcClient := jsonrpc.NewClient(client)
	if rpcClient == nil {
		return errors.New("Failed to connect to policy server")

	}

	if err := rpcClient.Call(remoteMethodCall, request, response); err != nil {
		return err
	}

	request.EventType = monitor.EventDestroy

	return rpcClient.Call(remoteMethodCall, request, response)
}
