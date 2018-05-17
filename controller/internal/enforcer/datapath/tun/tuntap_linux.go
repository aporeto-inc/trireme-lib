// +build linux

package tundatapath

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"os/exec"
	"strconv"
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
func NewTunDataPath(processor datapathimpl.DataPathPacketHandler, markoffset int, mode constants.ModeType) (datapathimpl.DatapathImpl, error) {
	needQueueingPolicy := false
	if mode != constants.RemoteContainer {
		needQueueingPolicy = true
	}
	//GetRlimit
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		return nil, fmt.Errorf("Unable to get current limit %s ", err)
	}

	//Set ulimit for open files here
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

	//Copy the buffer
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

	//Copy the buffer
	buffer := make([]byte, len(appPacket.Buffer)+appPacket.TCPOptionLength()+appPacket.TCPDataLength())
	copyIndex := copy(buffer, appPacket.Buffer)
	copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPOptions())
	copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPData())
	return writer.WriteSocket(buffer[:copyIndex])
}

func showIPrules() {
	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		zap.L().Error("ip command not found")
		fmt.Println("ip command not found")
		return
	}

	out, err := exec.Command(ipCmd, "rule", "list").Output()

	if err != nil {
		zap.L().Error("ip rule list returned error")
	} else {
		zap.L().Error("ip output",
			zap.String("out", string(out)))
	}
}

func cleanupNetworkIPRule() {
	// nolint
	var ipCmd string

	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		zap.L().Error("ip command not found")
		fmt.Println("ip command not found")
		return
	}

	showIPrules()

	cmd, err := exec.Command(ipCmd, "rule", "del", "prio", "0", "table", "10").Output()

	if err != nil {
		zap.L().Error("ip rule del prio 0 table 10 returned error ",
			zap.String("error", string(cmd)))
	}

	/*netlink.RuleDel(&netlink.Rule{
		Table:    NetworkRuleTable,
		Priority: RulePriority,
		Mark:     (cgnetcls.Initialmarkval - 1),
		Mask:     RuleMask,
	})*/
	//restore local rule again
	// nolint

	showIPrules()
	cmd, err = exec.Command(ipCmd, "rule", "add", "prio", "0", "table", "local").Output()

	if err != nil {
		zap.L().Error("ip rule add prio 0 table local returned error",
			zap.String("error", string(cmd)))
	}
	
	/*
	netlink.RuleAdd(&netlink.Rule{ //
		Table:    0xff, //
		Priority: 0x0,  //
		Mark:     0,    //
		Mask:     0,    //
	}) //  
        */
	//Delete prio 10 local rule
	// nolint

	/*
	netlink.RuleDel(&netlink.Rule{
		Table:    0xff,
		Priority: 0xa,
		Mark:     0,
		Mask:     0,
	})
        */

	showIPrules()
	cmd, err = exec.Command(ipCmd, "rule", "del", "prio", "10", "table", "local").Output()

	if err != nil {
		zap.L().Error("ip rule del prio 10 table local returned error",
			zap.String("error", string(cmd)))
	}
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

func (t *tundev) applyNetworkInterceptorTCConfig(deviceName string) {
	// We map cgroups from queue 1 to (numQueues - 1), queue 0
	// is the default queue where packets without cgroup lands in
	tcBatch, err := tcbatch.NewTCBatch(deviceName, 1, numQueues-1, 1, cgnetcls.Initialmarkval)
	if err != nil {
		zap.L().Fatal("Unable to setup queuing policy", zap.Error(err))
	}

	if err = tcBatch.BuildOutputTCBatchCommand(); err != nil {
		zap.L().Fatal("Unable to create queuing policy", zap.Error(err))
	}

	if err = tcBatch.Execute(); err != nil {
		zap.L().Fatal("Unable to install queuing policy", zap.Error(err))
	}
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

	//mac address not required for tun as of now
	t.tundeviceHdls[i], err = tuntap.NewTun(numQueues, ipaddress, []byte{}, deviceName, uint(uid), uint(gid), false, networkQueueCallBack)
	if err != nil {
		zap.L().Fatal("Received error while creating device ", zap.Error(err), zap.String("DeviceName", deviceName))
	}
	if t.needQueueingPolicy {
		t.applyNetworkInterceptorTCConfig(deviceName)
	}

	//Start Queues here
	for qIndex := 0; qIndex < int(numQueues); qIndex++ {
		if err = t.startNetworkSocket(qIndex, t.tundeviceHdls[i]); err != nil {
			zap.L().Fatal("Failed to start network socket for queue %d: %s", zap.Int("queueNum", qIndex), zap.Error(err))
		}
	}
	var intf *net.Interface
	// Program Route in the tables
	intf, err = net.InterfaceByName(deviceName)
	if err != nil {
		zap.L().Fatal("Failed to retrieve device ", zap.String("DeviceName", deviceName))
	}
	route := &netlink.Route{
		Table:     NetworkRuleTable,
		Gw:        net.ParseIP(ipaddress),
		LinkIndex: intf.Index,
	}

	if err = iprouteHdl.AddRoute(route); err != nil {
		// We are initing here refuse to start if this fails
		zap.L().Fatal("Unable to add ip route", zap.Error(err), zap.String("IP Address", net.ParseIP(ipaddress).String()), zap.Int("Table", NetworkRuleTable), zap.Int("Interface Index", intf.Index))

	}
	return nil
}

func cleanupApplicationIPRule() {
	//Cleanup on exit
	// nolint
	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		zap.L().Error("ip command not found")
		fmt.Println("ip command not found")
		return
	}

	showIPrules()

	cmd, err := exec.Command(ipCmd, "rule", "del", "prio", "0", "table", "11").Output()

	if err != nil {
		zap.L().Error("ip rule del prio 0 table 11 returned error",
			zap.String("error", string(cmd)))
	}

/*	netlink.RuleAdd(&netlink.Rule{
		Table:    ApplicationRuleTable,
		Priority: RulePriority,
		Mark:     cgnetcls.Initialmarkval - 2,
		Mask:     RuleMask,
	})
*/
}

func (t *tundev) applyApplicationInterceptorTCConfig(deviceName string) {

	// We map cgroups from queue 1 to (numQueues - 1), queue 0
	// is the default queue where packets without cgroup lands in
	tcBatch, err := tcbatch.NewTCBatch(deviceName, 1, numQueues-1, 1, cgnetcls.Initialmarkval)
	if err != nil {
		zap.L().Fatal("Unable to setup queuing policy", zap.Error(err))
	}

	if err = tcBatch.BuildOutputTCBatchCommand(); err != nil {
		zap.L().Fatal("Unable to create queuing policy", zap.Error(err))
	}

	if err = tcBatch.Execute(); err != nil {
		zap.L().Fatal("Unable to install queuing policy", zap.Error(err))
	}
}

func (t *tundev) startApplicationSocket(qIndex int, tun *tuntap.TunTap) {
	writer, err := afinetrawsocket.CreateSocket(afinetrawsocket.ApplicationRawSocketMark, "tun-in1")
	if err != nil {
		zap.L().Fatal("Cannot bring up write path for tun interface", zap.Error(err))
	}
	go tun.StartQueue(qIndex, &privateData{
		t:        t,
		queueNum: qIndex,
		writer:   writer,
	})
}
func (t *tundev) startApplicationInterceptorInstance(i int) {
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

	//mac address not required for tun as of now
	t.tundeviceHdls[i], err = tuntap.NewTun(numQueues, ipaddress, []byte{}, deviceName, uint(uid), uint(gid), false, appQueueCallBack)
	if err != nil {
		zap.L().Fatal("Received error while creating device ", zap.Error(err), zap.String("DeviceName", deviceName))
	}
	if t.needQueueingPolicy {
		t.applyApplicationInterceptorTCConfig(deviceName)
	}

	// StartQueue here after we have create device and setup tc queueing.
	// Once we setup routes we can get traffic
	for qIndex := 0; qIndex < int(numQueues); qIndex++ {
		t.startApplicationSocket(qIndex, t.tundeviceHdls[i])
	}

	// Program Route in the tables
	intf, err := net.InterfaceByName(deviceName)
	if err != nil {
		zap.L().Fatal("Failed to retrieve device ", zap.String("DeviceName", deviceName))
	}

	route := &netlink.Route{
		Table:     ApplicationRuleTable,
		Gw:        net.ParseIP(ipaddress),
		LinkIndex: intf.Index,
	}

	if err := iprouteHdl.AddRoute(route); err != nil {
		// We are initing here refuse to start if this fails
		zap.L().Fatal("Unable to add ip route", zap.Error(err), zap.String("IP Address", net.ParseIP(ipaddress).String()), zap.Int("Table", NetworkRuleTable), zap.Int("Interface Index", intf.Index))
	}
}

func setIPRulesApplication(ctx context.Context) {
	zap.L().Error("Setting up ip rules application")
	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		zap.L().Error("ip command not found")
		return
	}

	showIPrules()
			
	cmd, err := exec.Command(ipCmd, "rule", "add", "prio", "1", "fwmark", "0xfe/0xffff", "table", "11").Output()

	if err != nil {
		zap.L().Error("ip rule add prio 0 fwmark 0xfe/0xffff table 11 returned error",
			zap.String("error", string(cmd)))
	}

	go func() {
		<-ctx.Done()
		cleanupApplicationIPRule()
	}()
}

func setIPRulesNetwork(ctx context.Context) {
	zap.L().Error("Setting up ip rules network")
	ipCmd, err := exec.LookPath("ip")
	if err != nil {
		zap.L().Error("ip command not found")
		return
	}

	showIPrules()
	cmd, err := exec.Command(ipCmd, "rule", "add", "prio", "10", "table", "local").Output()

	if err != nil {
		zap.L().Error("ip rule add prio 10 table local returned error",
			zap.String("error", string(cmd)))
	}

	showIPrules()
	cmd, err = exec.Command(ipCmd, "rule", "del", "prio", "0", "table", "local").Output()

	if err != nil {
		zap.L().Error("ip rule del prio 0 table local returned error",
			zap.String("error", string(cmd)))
	}

	showIPrules()
	cmd, err = exec.Command(ipCmd, "rule", "add", "prio", "0", "fwmark", "0xff/0xffff", "table", "10").Output()

	if err != nil {
		zap.L().Error("ip rule add prio 0 fwmark 0xff/0xffff table 10 returned error",
			zap.String("error", string(cmd)))
	}

	//Startup a cleanup routine here.
	go func() {
		//Cleanup on exit
		<-ctx.Done()
		cleanupNetworkIPRule()
	}()
}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (t *tundev) StartApplicationInterceptor(ctx context.Context) {
	if numTunDevicesPerDirection > 255 {
		zap.L().Fatal("Cannot create more than 255 devices per direction")
	}

	for i := 0; i < numTunDevicesPerDirection; i++ {
		t.startApplicationInterceptorInstance(i)
	}

	setIPRulesApplication(ctx)
}

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (t *tundev) StartNetworkInterceptor(ctx context.Context) {
	if numTunDevicesPerDirection > 255 {
		zap.L().Fatal("Cannot create more than 255 devices per direction")
	}


	for i := 0; i < numTunDevicesPerDirection; i++ {
		// nolint
		t.startNetworkInterceptorInstance(i)
	}

	setIPRulesNetwork(ctx)
}

