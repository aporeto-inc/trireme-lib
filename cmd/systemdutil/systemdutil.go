package main

import (
	"errors"
	"log"
	"net"
	"net/rpc/jsonrpc"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	docopt "github.com/docopt/docopt-go"
)

const (
	remoteMethodCall = "Server.HandleEvent"
	contextID        = "unused"
	//rpcMonitorChannel = "/var/run/monitor.sock"
)

func main() {

	usage := `Command for launching programs with aporeto policy.
Usage:
  aporetolaunch [-h] | [--servicename=sname] [--command=bin] [--params=parameter...] [--metadata=keyvalue...] | <exiting>
 aporetolaunch --version
Options:
  -h --help                              show this help message and exit
  -s sname --servicename=sname           the name of the service to be launched
  -c bin --command=bin                   The command to run
  -p parameters --params=parameters      the parameter passed to the command
  -m keyvalue --metadata=keyvalue        The metadata/labels associated with a service
  --version                              show version and exit
  `
	stderrlogger := log.New(os.Stderr, "", 0)
	arguments, _ := docopt.Parse(usage, nil, true, "1.0.0rc2", false)
	servicename, ok := arguments["--servicename"].(string)

	command, _ := arguments["--command"].(string)
	if !ok {
		servicename = command
	}
	params := arguments["--params"].([]string)
	metadata := arguments["--metadata"]
	metadatamap := make(map[string]string)
	exiting_cgroup, _ := arguments["<exiting>"]

	if exiting_cgroup != nil {
		if len(exiting_cgroup.(string)) > 0 {
			err := HandleCgroupStop(exiting_cgroup.(string))
			if err != nil {
				stderrlogger.Fatalf("Cannot connect to policy process %s. Resources not deleted\n", err)
				os.Exit(-1)
			}
			os.Exit(0)
		}
	}

	for _, element := range metadata.([]string) {
		keyvalue := strings.Split(element, "=")
		metadatamap[keyvalue[0]] = keyvalue[1]
	}

	//Make RPC call
	//In Response i expect a status of OK or !OK
	client, err := net.Dial("unix", rpcmonitor.Rpcaddress)
	if err != nil {
		// log.WithFields(log.Fields{"package":"aporetolaunch",
		// 	"error":err.Error()}).Error("Cannot connect to policy process")
		stderrlogger.Fatalf("Cannot connect to policy process %s", err)
	}

	//This is added since the release_notification comes in this format
	//Easier to massage it while creation rather than change at the receiving end depending on event
	request := &rpcmonitor.EventInfo{
		PUID:      "/" + strconv.Itoa(os.Getpid()),
		Name:      servicename,
		Tags:      metadatamap,
		PID:       strconv.Itoa(os.Getpid()),
		EventType: "start",
	}
	response := &rpcmonitor.RPCResponse{}

	rpcClient := jsonrpc.NewClient(client)
	err = rpcClient.Call(remoteMethodCall, request, response)
	if err != nil {
		// log.WithFields(log.Fields{"package":"aporetolaunch",
		// 	"error":err.Error()}).Error("Remote Call to policy process failed")
		stderrlogger.Fatalf("Policy Server call failed %s", err.Error())
		os.Exit(-1)
	}

	if len(response.Error) > 0 {
		//Policy failed
		stderrlogger.Fatalf("Your policy does not allow you to run this command")

	}

	syscall.Exec(command, params, os.Environ())

}

func HandleCgroupStop(cgroupName string) error {

	client, err := net.Dial("unix", rpcmonitor.Rpcaddress)
	if err != nil {
		return err
	}

	request := &rpcmonitor.EventInfo{
		PUID:      cgroupName,
		Name:      cgroupName,
		Tags:      nil,
		PID:       strconv.Itoa(os.Getpid()),
		EventType: "stop",
	}
	response := &rpcmonitor.RPCResponse{}

	rpcClient := jsonrpc.NewClient(client)
	if rpcClient == nil {
		return errors.New("Failed to connect to policy server")

	}

	return rpcClient.Call(remoteMethodCall, request, response)
}
