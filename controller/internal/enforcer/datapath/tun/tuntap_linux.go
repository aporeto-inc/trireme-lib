// +build linux

package tundatapath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"syscall"

	"github.com/aporeto-inc/trireme-lib/controller/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapath/tun/utils/afinetrawsocket"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapath/tun/utils/iproute"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapath/tun/utils/tcbatch"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapath/tun/utils/tuntap"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapathimpl"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

type tundev struct {
	processor                 datapathimpl.DataPathPacketHandler
	numTunDevicesPerDirection uint8
	tundeviceHdls             []*tuntap.TunTap
	needQueueingPolicy        bool
}

type privateData struct {
	t        *tundev
	queueNum int
	writer   afinetrawsocket.SocketWriter
}

var numQueues uint16

func init() {
	numQueues = maxNumQueues
}

func networkQueueCallBack(data []byte, cbData interface{}) error {
	return cbData.(*privateData).t.processNetworkPacketFromTun(data, cbData.(*privateData).queueNum, cbData.(*privateData).writer)
}

func appQueueCallBack(data []byte, cbData interface{}) error {
	return cbData.(*privateData).t.processAppPacketFromTun(data, cbData.(*privateData).queueNum, cbData.(*privateData).writer)
}

// NewTunDataPath instantiates a new tundatapath
func NewTunDataPath(processor datapathimpl.DataPathPacketHandler, mode constants.ModeType) (datapathimpl.DatapathImpl, error) {

	needQueueingPolicy := false
	if mode != constants.RemoteContainer {
		needQueueingPolicy = true
	}

	// GetRlimit
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		return nil, fmt.Errorf("Unable to get current limit %s ", err)
	}

	// Set ulimit for open files here
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		return nil, fmt.Errorf("Unable to set ulimit for open files %s", err)
	}

	return &tundev{
		processor:                 processor,
		numTunDevicesPerDirection: numTunDevicesPerDirection,
		tundeviceHdls:             make([]*tuntap.TunTap, numTunDevicesPerDirection),
		needQueueingPolicy:        needQueueingPolicy,
	}, nil
}

func (t *tundev) processNetworkPacketFromTun(data []byte, queueNum int, writer afinetrawsocket.SocketWriter) error {

	netPacket, err := packet.New(packet.PacketTypeNetwork, data, strconv.Itoa(queueNum-1+cgnetcls.Initialmarkval))
	if err != nil {
		return fmt.Errorf("Unable to create packet %s", err)
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		if err = t.processor.ProcessNetworkPacket(netPacket); err != nil {
			return fmt.Errorf("Network bad packet %s", err)
		}
	} else {
		return fmt.Errorf("Invalid ip protocol: %d", netPacket.IPProto)
	}

	// Copy the buffer
	buffer := make([]byte, len(netPacket.Buffer)+netPacket.TCPOptionLength()+netPacket.TCPDataLength())
	copyIndex := copy(buffer, netPacket.Buffer)
	copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPOptions())
	copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPData())
	return writer.WriteSocket(buffer[:copyIndex])
}

func (t *tundev) processAppPacketFromTun(data []byte, queueNum int, writer afinetrawsocket.SocketWriter) error {

	appPacket, err := packet.New(packet.PacketTypeApplication, data, strconv.Itoa(queueNum-1+cgnetcls.Initialmarkval))
	if err != nil {
		return fmt.Errorf("Unable to create packet %s", err)
	} else if appPacket.IPProto == packet.IPProtocolTCP {
		if err = t.processor.ProcessApplicationPacket(appPacket); err != nil {
			return fmt.Errorf("Application bad packet %s", err)
		}
	} else {
		return fmt.Errorf("Invalid ip protocol: %d", appPacket.IPProto)
	}

	// Copy the buffer
	buffer := make([]byte, len(appPacket.Buffer)+appPacket.TCPOptionLength()+appPacket.TCPDataLength())
	copyIndex := copy(buffer, appPacket.Buffer)
	copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPOptions())
	copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPData())
	return writer.WriteSocket(buffer[:copyIndex])
}

func (t *tundev) startNetworkSocket(qIndex int, tun *tuntap.TunTap) error {

	writer, err := afinetrawsocket.CreateSocket(afinetrawsocket.NetworkRawSocketMark, "tun-out1")
	if err != nil {
		return err
	}

	go tun.StartQueue(qIndex, &privateData{
		t:        t,
		queueNum: qIndex,
		writer:   writer,
	})
	return nil
}

func (t *tundev) applyNetworkInterceptorTCConfig(deviceName string) error {

	// We map cgroups from queue 1 to (numQueues - 1), queue 0
	// is the default queue where packets without cgroup lands in
	tcBatch, err := tcbatch.NewTCBatch(deviceName, 1, numQueues-1, 1, cgnetcls.Initialmarkval)
	if err != nil {
		return err
	}

	if err = tcBatch.BuildOutputTCBatchCommand(); err != nil {
		return err
	}

	return tcBatch.Execute()
}

func (t *tundev) startNetworkInterceptorInstance(i int) (err error) {

	iprouteHdl, _ := iproute.NewIPRouteHandle()
	deviceName := baseTunDeviceName + baseTunDeviceInput + strconv.Itoa(i+1)
	ipaddress := tunIPAddressSubnetIn + strconv.Itoa(i+1)

	uid := 0
	gid := 0
	var currentUser *user.User
	if currentUser, err = user.Current(); err == nil {
		uid, _ = strconv.Atoi(currentUser.Uid)
		gid, _ = strconv.Atoi(currentUser.Gid)
	}

	/// MAC address not required for tun as of now
	t.tundeviceHdls[i], err = tuntap.NewTun(numQueues, ipaddress, []byte{}, deviceName, uint(uid), uint(gid), false, networkQueueCallBack)
	if err != nil {
		return fmt.Errorf("Failed to create device %s %s", deviceName, err)
	}
	if t.needQueueingPolicy {
		if err = t.applyNetworkInterceptorTCConfig(deviceName); err != nil {
			return fmt.Errorf("Failed to setup TC config on device %s %s", deviceName, err)
		}
	}

	// Start Queues here
	for qIndex := 0; qIndex < int(numQueues); qIndex++ {
		if err = t.startNetworkSocket(qIndex, t.tundeviceHdls[i]); err != nil {
			return fmt.Errorf("Failed to start network socket for queue %d: %s", qIndex, err.Error())
		}
	}

	var intf *net.Interface
	// Program Route in the tables
	intf, err = net.InterfaceByName(deviceName)
	if err != nil {
		return fmt.Errorf("Failed to retrieve device %s", deviceName)
	}

	route := &netlink.Route{
		Table:     NetworkRuleTable,
		Gw:        net.ParseIP(ipaddress),
		LinkIndex: intf.Index,
	}

	if err = iprouteHdl.AddRoute(route); err != nil {
		return fmt.Errorf("Unable to add ip route %v rttbl: %v if:%v err:%v", net.ParseIP(ipaddress).String(), NetworkRuleTable, intf.Index, err.Error())
	}

	return nil
}

func (t *tundev) applyApplicationInterceptorTCConfig(deviceName string) error {

	// We map cgroups from queue 1 to (numQueues - 1), queue 0
	// is the default queue where packets without cgroup lands in
	tcBatch, err := tcbatch.NewTCBatch(deviceName, 1, numQueues-1, 1, cgnetcls.Initialmarkval)
	if err != nil {
		return fmt.Errorf("Unable to setup queuing policy: %s", err)
	}

	if err = tcBatch.BuildOutputTCBatchCommand(); err != nil {
		return fmt.Errorf("Unable to create queuing policy: %s", err)
	}

	if err = tcBatch.Execute(); err != nil {
		return fmt.Errorf("Unable to install queuing policy: %s", err)
	}

	return nil
}

func (t *tundev) startApplicationSocket(qIndex int, tun *tuntap.TunTap) error {

	writer, err := afinetrawsocket.CreateSocket(afinetrawsocket.ApplicationRawSocketMark, "tun-in1")
	if err != nil {
		return fmt.Errorf("Cannot bring up write path for tun interface %s", err.Error())
	}
	go tun.StartQueue(qIndex, &privateData{
		t:        t,
		queueNum: qIndex,
		writer:   writer,
	})

	return nil
}

func (t *tundev) startApplicationInterceptorInstance(i int) error {

	iprouteHdl, _ := iproute.NewIPRouteHandle()
	deviceName := baseTunDeviceName + baseTunDeviceOutput + strconv.Itoa(i+1)
	ipaddress := tunIPAddressSubnetOut + strconv.Itoa(i+1)

	var err error
	uid := 0
	gid := 0
	var currentUser *user.User
	if currentUser, err = user.Current(); err == nil {
		uid, _ = strconv.Atoi(currentUser.Uid)
		gid, _ = strconv.Atoi(currentUser.Gid)
	}

	// MAC address not required for tun as of now
	t.tundeviceHdls[i], err = tuntap.NewTun(numQueues, ipaddress, []byte{}, deviceName, uint(uid), uint(gid), false, appQueueCallBack)
	if err != nil {
		return fmt.Errorf("Failed to create device %s %s", deviceName, err)
	}
	if t.needQueueingPolicy {
		if err = t.applyApplicationInterceptorTCConfig(deviceName); err != nil {
			return fmt.Errorf("Failed to setup TC config on device %s %s", deviceName, err)
		}
	}

	// StartQueue here after we have create device and setup tc queueing.
	// Once we setup routes we can get traffic
	for qIndex := 0; qIndex < int(numQueues); qIndex++ {
		err = t.startApplicationSocket(qIndex, t.tundeviceHdls[i])

		if err != nil {
			return fmt.Errorf("Failed to create application socket for queue %d. Error: %s", qIndex, err.Error())
		}
	}

	// Program Route in the tables
	intf, err := net.InterfaceByName(deviceName)
	if err != nil {
		return fmt.Errorf("Failed to retrieve device %s", deviceName)
	}

	route := &netlink.Route{
		Table:     ApplicationRuleTable,
		Gw:        net.ParseIP(ipaddress),
		LinkIndex: intf.Index,
	}

	if err := iprouteHdl.AddRoute(route); err != nil {
		return fmt.Errorf("Unable to add ip route %v rttbl: %v if:%v err:%v", net.ParseIP(ipaddress).String(), NetworkRuleTable, intf.Index, err.Error())
	}

	return nil
}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (t *tundev) StartApplicationInterceptor(ctx context.Context) error {

	if numTunDevicesPerDirection > 255 {
		return errors.New("Cannot create more than 255 devices per direction")
	}

	for i := 0; i < numTunDevicesPerDirection; i++ {
		if err := t.startApplicationInterceptorInstance(i); err != nil {
			return fmt.Errorf("Unable to start application interceptor instance: %s", err.Error())
		}
	}

	setIPRulesApplication(ctx)
	showIPrules()

	return nil
}

// startNetworkInterceptor will create a interceptor that processes packets
// coming from the network
func (t *tundev) StartNetworkInterceptor(ctx context.Context) error {

	if numTunDevicesPerDirection > 255 {
		return errors.New("Cannot create more than 255 devices per direction")
	}

	for i := 0; i < numTunDevicesPerDirection; i++ {
		if err := t.startNetworkInterceptorInstance(i); err != nil {
			return fmt.Errorf("Unable to start network interceptor instance: %s", err)
		}
	}

	setIPRulesNetwork(ctx)
	showIPrules()

	return nil
}

// CleanUp is the clean up routine for the datapath.
func (t *tundev) CleanUp() error {

	var appError, netError error
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		appError = cleanupApplicationIPRule()
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		netError = cleanupNetworkIPRule()
		wg.Done()
	}()

	wg.Wait()

	ret := ""
	if appError != nil {
		ret = "app: " + appError.Error()
	}

	if netError != nil {
		ret = "net: " + netError.Error()
	}
	return errors.New(ret)
}

func setIPRulesApplication(ctx context.Context) error {

	zap.L().Debug("Setting up ip rules application")

	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		return err
	}

	return exec.Command(ipCmd, "rule", "add", "prio", "1", "fwmark", "0xfe/0xffff", "table", "11").Run()
}

func cleanupApplicationIPRule() error {

	zap.L().Debug("Cleaning up ip rules application")

	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		return err
	}

	return exec.Command(ipCmd, "rule", "del", "prio", "1", "table", "11").Run()
}

func setIPRulesNetwork(ctx context.Context) error {

	zap.L().Debug("Setting up ip rules network")

	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		return err
	}

	ret := ""
	err = exec.Command(ipCmd, "rule", "add", "prio", "10", "table", "local").Run()
	if err != nil {
		ret = "cmd1: " + err.Error() + " "
	}

	err = exec.Command(ipCmd, "rule", "del", "prio", "0", "table", "local").Run()
	if err != nil {
		ret = ret + "cmd2: " + err.Error() + " "
	}

	err = exec.Command(ipCmd, "rule", "add", "prio", "0", "fwmark", "0xff/0xffff", "table", "10").Run()
	if err != nil {
		ret = ret + "cmd3: " + err.Error() + " "
	}

	if ret != "" {
		return errors.New(ret)
	}

	return nil
}

func cleanupNetworkIPRule() error {

	zap.L().Debug("Cleaning up ip rules network")

	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		return err
	}

	ret := ""
	err = exec.Command(ipCmd, "rule", "del", "prio", "0", "table", "10").Run()
	if err != nil {
		ret = "cmd1: " + err.Error() + " "
	}

	err = exec.Command(ipCmd, "rule", "add", "prio", "0", "table", "local").Run()
	if err != nil {
		ret = ret + "cmd2: " + err.Error() + " "
	}

	err = exec.Command(ipCmd, "rule", "del", "prio", "10", "table", "local").Run()
	if err != nil {
		ret = ret + "cmd3: " + err.Error() + " "
	}

	if ret != "" {
		return errors.New(ret)
	}

	return nil
}

func showIPrules() {

	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		zap.L().Error("ip command not found")
		return
	}

	out, err := exec.Command(ipCmd, "rule", "list").Output()

	if err != nil {
		zap.L().Warn("ip rule list returned error")
	} else {
		zap.L().Info("ip output",
			zap.String("out", string(out)))
	}
}
