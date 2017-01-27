package systemdutil

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"os"
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

	stderrlogger := log.New(os.Stderr, "", 0)

	if arguments["<cgroup>"] != nil && len(arguments["<cgroup>"].(string)) > 0 {
		exitingCgroup := arguments["<cgroup>"].(string)

		if err := HandleCgroupStop(exitingCgroup); err != nil {
			err = fmt.Errorf("Cannot connect to policy process %s. Resources not deleted\n", err)
			stderrlogger.Print(err)
			return err
		}

		return nil
	}

	command := ""
	metadata := []string{}
	servicename := ""
	params := []string{}

	if arguments["run"].(bool) {

		command = arguments["<command>"].(string)

		if args, ok := arguments["--label"]; ok && args != nil {
			metadata = args.([]string)
		}

		if args, ok := arguments["--service-name"]; ok && args != nil {
			servicename = args.(string)
		}

		if args, ok := arguments["<params>"]; ok && args != nil {
			params = args.([]string)
		}
	}

	metadatamap, err := createMetadata(servicename, metadata)

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
		Name:      command,
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

	syscall.Exec(command, params, os.Environ())

	return nil
}

// createMetadata extracts the relevant metadata
func createMetadata(servicename string, metadata []string) (map[string]string, error) {

	metadatamap := map[string]string{}

	for _, element := range metadata {
		keyvalue := strings.Split(element, "=")

		if len(keyvalue) != 2 {
			return nil, fmt.Errorf("Invalid metadata")
		}

		if keyvalue[0][0] == []byte("$")[0] {
			return nil, fmt.Errorf("Metadata cannot start with $")
		}

		metadatamap[keyvalue[0]] = keyvalue[1]
	}

	if servicename != "" {
		metadatamap["$servicename"] = servicename
	}

	return metadatamap, nil
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

	if err := rpcClient.Call(remoteMethodCall, request, response); err != nil {
		return err
	}

	return nil
}
