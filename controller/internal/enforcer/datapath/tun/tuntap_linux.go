// +build linux

package tundatapath

import (
	"context"
	"fmt"
	"net"
	"os/user"
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

	cleanupApplicationIPRule()
	cleanupNetworkIPRule()
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

	zap.L().Debug("Recieved Network packet from Tun")
	if err != nil {
		zap.L().Debug("Error creating new packet")
		return fmt.Errorf("Unable to create packet %s", err)
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		if err = t.processor.ProcessNetworkPacket(netPacket); err != nil {
			return fmt.Errorf("Network bad TCP packet %s", err)
		}
		//Copy the buffer
		buffer := make([]byte, len(netPacket.Buffer)+netPacket.TCPOptionLength()+netPacket.TCPDataLength())
		copyIndex := copy(buffer, netPacket.Buffer)
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPData())
		return writer.WriteSocket(buffer[:copyIndex])

	} else if netPacket.IPProto == packet.IPProtocolUDP {
		zap.L().Debug("Varks: Processing Network UDP Packet")
		if err = t.processor.ProcessNetworkUDPPacket(netPacket); err != nil {
			return fmt.Errorf("Network bad UDP Packet %s", err)
		}
	}
	return fmt.Errorf("Invalid ip protocol: %d", netPacket.IPProto)
}

func (t *tundev) processAppPacketFromTun(data []byte, queueNum int, writer afinetrawsocket.SocketWriter) error {
	zap.L().Error("Received Packet on queue", zap.Int("QUE", queueNum), zap.Int("MARK", queueNum-1+cgnetcls.Initialmarkval))
	appPacket, err := packet.New(packet.PacketTypeApplication, data, strconv.Itoa(queueNum-1+cgnetcls.Initialmarkval))

	if err != nil {
		zap.L().Debug("Varks: Error creating new packet- app side", zap.Error(err))
		return fmt.Errorf("Unable to create packet %s", err)
	} else if appPacket.IPProto == packet.IPProtocolTCP {
		if err = t.processor.ProcessApplicationPacket(appPacket); err != nil {
			return fmt.Errorf("Application bad TCP packet %s", err)
		}

		//Copy the buffer
		buffer := make([]byte, len(appPacket.Buffer)+appPacket.TCPOptionLength()+appPacket.TCPDataLength())
		copyIndex := copy(buffer, appPacket.Buffer)
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPData())
		return writer.WriteSocket(buffer[:copyIndex])
	} else if appPacket.IPProto == packet.IPProtocolUDP {
		zap.L().Debug("Processing App udp packet of length", zap.Reflect("length", len(appPacket.Buffer)))
		if err = t.processor.ProcessApplicationUDPPacket(appPacket); err != nil {
			return fmt.Errorf("Application bad UDP packet %s", err)
		}
	}
	return fmt.Errorf("Invalid ip protocol: %d", appPacket.IPProto)
}

func cleanupNetworkIPRule() {
	// nolint
	iprouteHdl, _ := iproute.NewIPRouteHandle()

	iprouteHdl.DeleteRule(&netlink.Rule{
		Table:    NetworkRuleTable,
		Priority: RulePriority,
		Mark:     (cgnetcls.Initialmarkval - 1),
		Mask:     RuleMask,
	})
	//restore local rule again
	// nolint
	iprouteHdl.AddRule(&netlink.Rule{
		Table:    0xff,
		Priority: 0x0,
		Mark:     0,
		Mask:     0,
	})

	//Delete prio 10 local rule
	// nolint
	iprouteHdl.DeleteRule(&netlink.Rule{
		Table:    0xff,
		Priority: 0xa,
		Mark:     0,
		Mask:     0,
	})
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

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (t *tundev) StartNetworkInterceptor(ctx context.Context) {
	iprouteHdl, _ := iproute.NewIPRouteHandle()

	if numTunDevicesPerDirection > 255 {
		zap.L().Fatal("Cannot create more than 255 devices per direction")
	}

	//Reduce prio of local table so our rules get hit before even for local traffic
	if err := iprouteHdl.AddRule(&netlink.Rule{
		Table:    0xff,
		Priority: 0xa,
		Mark:     0,
		Mask:     0,
	}); err != nil {
		zap.L().Fatal("Unable to add ip rule", zap.Error(err))
	}

	//Delete local table at prio 0
	if err := iprouteHdl.DeleteRule(&netlink.Rule{
		Table:    0xff,
		Priority: 0x0,
		Mark:     0,
		Mask:     0,
	}); err != nil {
		zap.L().Fatal("Unable to delete ip rule", zap.Error(err))
	}

	//Program ip route and ip rules
	if err := iprouteHdl.AddRule(&netlink.Rule{
		Table:    NetworkRuleTable,
		Priority: RulePriority,
		Mark:     (cgnetcls.Initialmarkval - 1),
		Mask:     RuleMask,
	}); err != nil {
		zap.L().Fatal("Unable to add ip rule", zap.Error(err))
	}

	//Startup a cleanup routine here.
	go func() {
		//Cleanup on exit
		<-ctx.Done()
		cleanupNetworkIPRule()
	}()

	for i := 0; i < numTunDevicesPerDirection; i++ {
		// nolint
		t.startNetworkInterceptorInstance(i)
	}
}

func cleanupApplicationIPRule() {
	//Cleanup on exit
	// nolint

	iprouteHdl, _ := iproute.NewIPRouteHandle()

	iprouteHdl.DeleteRule(&netlink.Rule{
		Table:    ApplicationRuleTable,
		Priority: RulePriority,
		Mark:     cgnetcls.Initialmarkval - 2,
		Mask:     RuleMask,
	})

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

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (t *tundev) StartApplicationInterceptor(ctx context.Context) {
	iprouteHdl, _ := iproute.NewIPRouteHandle()

	if numTunDevicesPerDirection > 255 {
		zap.L().Fatal("Cannot create more than 255 devices per direction")
	}

	if err := iprouteHdl.AddRule(&netlink.Rule{
		Table:    ApplicationRuleTable,
		Priority: RulePriority,
		Mark:     cgnetcls.Initialmarkval - 2,
		Mask:     RuleMask,
	}); err != nil {
		// We are initing here refuse to start if this fails
		zap.L().Fatal("Unable to add ip rule", zap.Error(err))

	}

	go func() {
		<-ctx.Done()
		cleanupApplicationIPRule()
	}()

	for i := 0; i < numTunDevicesPerDirection; i++ {
		t.startApplicationInterceptorInstance(i)
	}
}
