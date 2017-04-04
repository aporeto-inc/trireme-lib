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

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
)

const (
	remoteMethodCall = "Server.HandleEvent"
)

// ExecuteCommand executes a command in a cgroup and programs Trireme
func ExecuteCommand(arguments map[string]interface{}) error {

	var err error

	stderrlogger := log.New(os.Stderr, "", 0)

	if arguments["<cgroup>"] != nil && len(arguments["<cgroup>"].(string)) > 0 {
		exitingCgroup := arguments["<cgroup>"].(string)

		if err = HandleCgroupStop(exitingCgroup); err != nil {
			err = fmt.Errorf("cannot connect to policy process %s. Resources not deleted", err)
			stderrlogger.Print(err)
			return err
		}

		return nil
	}

	if !arguments["run"].(bool) {
		return fmt.Errorf("Bad arguments - no run command")
	}

	metadata := []string{}
	servicename := ""
	ports := "0"

	command := arguments["<command>"].(string)
	if !path.IsAbs(command) {
		command, err = exec.LookPath(command)
		if err != nil {
			return err
		}
	}

	if args, ok := arguments["--label"]; ok && args != nil {
		metadata = args.([]string)
	}

	if args, ok := arguments["--service-name"]; ok && args != nil {
		servicename = args.(string)
	}

	params := []string{command}
	if args, ok := arguments["<params>"]; ok && args != nil {
		params = append(params, args.([]string)...)
	}

	if args, ok := arguments["--ports"]; ok && args != nil {
		ports = args.(string)
	}

	name, metadatamap, err := createMetadata(servicename, command, ports, metadata)

	if err != nil {
		err = fmt.Errorf("Invalid metadata: %s", err)
		stderrlogger.Print(err)
		return err
	}

	// Make RPC call
	client, err := net.Dial("unix", rpcmonitor.DefaultRPCAddress)

	if err != nil {
		err = fmt.Errorf("Cannot connect to policy process %s", err)
		stderrlogger.Print(err)
		return err
	}

	//This is added since the release_notification comes in this format
	//Easier to massage it while creation rather than change at the receiving end depending on event
	request := &rpcmonitor.EventInfo{
		PUType:    constants.LinuxProcessPU,
		PUID:      "/" + strconv.Itoa(os.Getpid()),
		Name:      name,
		Tags:      metadatamap,
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

	return syscall.Exec(command, params, os.Environ())

}

// createMetadata extracts the relevant metadata
func createMetadata(servicename string, command string, ports string, metadata []string) (string, map[string]string, error) {

	metadatamap := map[string]string{}

	for _, element := range metadata {
		keyvalue := strings.Split(element, "=")

		if len(keyvalue) != 2 {
			return "", nil, fmt.Errorf("Invalid metadata")
		}

		if keyvalue[0][0] == []byte("$")[0] || keyvalue[0][0] == []byte("@")[0] {
			return "", nil, fmt.Errorf("Metadata cannot start with $ or @")
		}

		if keyvalue[0] == "port" || keyvalue[0] == "execpath" {
			return "", nil, fmt.Errorf("Metadata key cannot be port or execpath ")
		}

		metadatamap[keyvalue[0]] = keyvalue[1]
	}

	metadatamap["port"] = ports

	metadatamap["execpath"] = command

	name := command
	if servicename != "" {
		name = servicename
	}

	return name, metadatamap, nil
}

// HandleCgroupStop handles the deletion of a cgroup
func HandleCgroupStop(cgroupName string) error {

	client, err := net.Dial("unix", rpcmonitor.DefaultRPCAddress)
	if err != nil {
		return err
	}

	request := &rpcmonitor.EventInfo{
		PUType:    constants.LinuxProcessPU,
		PUID:      cgroupName,
		Name:      cgroupName,
		Tags:      nil,
		PID:       strconv.Itoa(os.Getpid()),
		EventType: monitor.EventStop,
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
