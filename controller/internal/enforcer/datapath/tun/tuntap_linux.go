// +build linux

package tundatapath

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"syscall"

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
	iprouteHdl                *iproute.Iproute
	//writeBackHdl              []*PacketWriter

}

type privateData struct {
	t        *tundev
	queueNum int
	writer   afinetrawsocket.SocketWriter
}

func networkQueueCallBack(data []byte, cbData interface{}) error {

	//	zap.L().Error("Received Network Packet", zap.Reflect("queueNum", cbData), zap.String("Address", fmt.Sprintf("%p", (cbData))), zap.String("\nHEX\n", string(hex.Dump(data))))

	if err := cbData.(*privateData).t.processNetworkPacketFromTun(data, cbData.(*privateData).queueNum, cbData.(*privateData).writer); err != nil {
		zap.L().Error("Received Netowrk Error", zap.Error(err))
	}
	return nil
}

func appQueueCallBack(data []byte, cbData interface{}) error {
	//zap.L().Error("Received Application Packet", zap.Reflect("queueNum", cbData), zap.String("Address", fmt.Sprintf("%p", (cbData))), zap.String("\nHEX\n", string(hex.Dump(data))))
	if err := cbData.(*privateData).t.processAppPacketFromTun(data, cbData.(*privateData).queueNum, cbData.(*privateData).writer); err != nil {
		zap.L().Error("Received Application Error", zap.Error(err))
	}
	return nil
}

// NewTunDataPath instantiates a new tundatapath
func NewTunDataPath(processor datapathimpl.DataPathPacketHandler, markoffset int) datapathimpl.DatapathImpl {

	ipr, err := iproute.NewIpRouteHandle()
	if err != nil {
		zap.L().Error("Unable to create an iproute handle")
		return nil
	}
	//GetRkunut
	var rlimit syscall.Rlimit
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		zap.L().Error("cannot Get Current limit  ", zap.Error(err))
	}

	//Set ulimit for open files here
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{
		Cur: rlimit.Cur,
		Max: 8192,
	}) //nolint
	return &tundev{
		processor:                 processor,
		numTunDevicesPerDirection: numTunDevicesPerDirection,
		tundeviceHdls:             make([]*tuntap.TunTap, numTunDevicesPerDirection),
		iprouteHdl:                ipr,
	}
}

func (t *tundev) processNetworkPacketFromTun(data []byte, queueNum int, writer afinetrawsocket.SocketWriter) error {
	netPacket, err := packet.New(packet.PacketTypeNetwork, data, strconv.Itoa(queueNum-1+cgnetcls.Initialmarkval))
	if err != nil {
		zap.L().Error("Error", zap.Error(err))
	}
	if err != nil {
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		err = t.processor.ProcessNetworkPacket(netPacket)
	} else {
		err = fmt.Errorf("invalid ip protocol: %d", netPacket.IPProto)
	}
	if err != nil {
		return err
	}
	//Copy the buffer
	buffer := make([]byte, len(netPacket.Buffer)+netPacket.TCPOptionLength()+netPacket.TCPDataLength())
	copyIndex := copy(buffer, netPacket.Buffer)
	copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPOptions())
	copyIndex += copy(buffer[copyIndex:], netPacket.GetTCPData())
	writer.WriteSocket(buffer[:copyIndex])
	return err
}

func (t *tundev) processAppPacketFromTun(data []byte, queueNum int, writer afinetrawsocket.SocketWriter) error {
	appPacket, err := packet.New(packet.PacketTypeApplication, data, strconv.Itoa(queueNum-1+cgnetcls.Initialmarkval))
	if err != nil {
	} else if appPacket.IPProto == packet.IPProtocolTCP {
		err = t.processor.ProcessApplicationPacket(appPacket)
	} else {
		err = fmt.Errorf("invalid ip protocol: %d", appPacket.IPProto)
	}

	if err == nil {
		//Copy the buffer
		buffer := make([]byte, len(appPacket.Buffer)+appPacket.TCPOptionLength()+appPacket.TCPDataLength())
		copyIndex := copy(buffer, appPacket.Buffer)
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPOptions())
		copyIndex += copy(buffer[copyIndex:], appPacket.GetTCPData())
		writer.WriteSocket(buffer[:copyIndex])
	}

	//writer.WriteSocket(data)
	return err

}

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (t *tundev) StartNetworkInterceptor(ctx context.Context) {
	if numTunDevicesPerDirection > 255 {
		zap.L().Fatal("Cannot create more than 255 devices per direction")
	}

	//Reduce prio of local table so our rules get hit before even for local traffic
	if err := t.iprouteHdl.AddRule(&netlink.Rule{
		Table:    0xff,
		Priority: 0xa,
		Mark:     0,
		Mask:     0,
	}); err != nil {
		// We are initing here refuse to start if this fails
		zap.L().Error("Unable to add ip rule", zap.Error(err))

	}

	//Delete local table at prio 0
	if err := t.iprouteHdl.DeleteRule(&netlink.Rule{
		Table:    0xff,
		Priority: 0x0,
		Mark:     0,
		Mask:     0,
	}); err != nil {
		// We are initing here refuse to start if this fails
		zap.L().Error("Unable to delete ip rule", zap.Error(err))

	}
	//Program ip route and ip rules
	if err := t.iprouteHdl.AddRule(&netlink.Rule{
		Table:    NetworkRuleTable,
		Priority: RulePriority,
		Mark:     (cgnetcls.Initialmarkval - 1),
		Mask:     RuleMask,
	}); err != nil {
		// We are initing here refuse to start if this fails
		zap.L().Fatal("Unable to add ip rule", zap.Error(err))

	}

	//Startup a cleanup routine here.
	go func() {
		//Cleanup on exit
		<-ctx.Done()
		t.iprouteHdl.DeleteRule(&netlink.Rule{
			Table:    NetworkRuleTable,
			Priority: RulePriority,
			Mark:     (cgnetcls.Initialmarkval - 1),
			Mask:     RuleMask,
		}) // nolint
		//restore local rule again
		t.iprouteHdl.AddRule(&netlink.Rule{
			Table:    0xff,
			Priority: 0x0,
			Mark:     0,
			Mask:     0,
		}) //nolint

		//Delete prio 10 local rule
		t.iprouteHdl.DeleteRule(&netlink.Rule{
			Table:    0xff,
			Priority: 0xa,
			Mark:     0,
			Mask:     0,
		}) //nolint
	}()
	for i := 0; i < numTunDevicesPerDirection; i++ {
		deviceName := baseTunDeviceName + baseTunDeviceInput + strconv.Itoa(i+1)
		ipaddress := tunIPAddressSubnetIn + strconv.Itoa(i+1)

		uid := 0
		gid := 0
		if user, err := user.Current(); err == nil {
			uid, _ = strconv.Atoi(user.Uid)
			gid, _ = strconv.Atoi(user.Gid)
		}
		//mac address not required for tun as of now
		if tun, err := tuntap.NewTun(255, ipaddress, []byte{}, deviceName, uint(uid), uint(gid), false, networkQueueCallBack); err == nil {
			t.tundeviceHdls[i] = tun
			// Program Route in the tables
			intf, err := net.InterfaceByName(deviceName)
			if err != nil {
				zap.L().Fatal("Failed to retrieve device ", zap.String("DeviceName", deviceName))
			}

			//Start Queues here
			for qIndex := 0; qIndex < 255; qIndex++ {
				pData := &privateData{
					t:        t,
					queueNum: qIndex,
				}
				if writer, err := afinetrawsocket.CreateSocket(dummyIPAddress, afinetrawsocket.NetworkRawSocketMark, "tun-out1"); err == nil {
					pData.writer = writer
					go tun.StartQueue(qIndex, pData)
					continue
				} else {
					zap.L().Error("CreateSocket Error %s", zap.Error(err))
				}
				//go rawloop(qIndex, tun, "network")

			}

			route := &netlink.Route{
				Table:     NetworkRuleTable,
				Gw:        net.ParseIP(ipaddress),
				LinkIndex: intf.Index,
			}

			if err := t.iprouteHdl.AddRoute(route); err != nil {
				// We are initing here refuse to start if this fails
				zap.L().Fatal("Unable to add ip route", zap.Error(err), zap.String("IP Address", net.ParseIP(ipaddress).String()), zap.Int("Table", NetworkRuleTable), zap.Int("Interface Index", intf.Index))

			}
		} else {
			zap.L().Fatal("Received error while creating device ", zap.Error(err), zap.String("DeviceName", deviceName))
		}

	}
}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (t *tundev) StartApplicationInterceptor(ctx context.Context) {
	if numTunDevicesPerDirection > 255 {
		zap.L().Fatal("Cannot create more than 255 devices per direction")
	}

	if err := t.iprouteHdl.AddRule(&netlink.Rule{
		Table:    ApplicationRuleTable,
		Priority: RulePriority,
		Mark:     cgnetcls.Initialmarkval - 2,
		Mask:     RuleMask,
	}); err != nil {
		// We are initing here refuse to start if this fails
		zap.L().Fatal("Unable to add ip rule", zap.Error(err))

	}
	go func() {
		//Cleanup on exit
		<-ctx.Done()
		t.iprouteHdl.DeleteRule(&netlink.Rule{
			Table:    ApplicationRuleTable,
			Priority: RulePriority,
			Mark:     cgnetcls.Initialmarkval - 2,
			Mask:     RuleMask,
		}) // nolint

	}()

	for i := 0; i < numTunDevicesPerDirection; i++ {
		deviceName := baseTunDeviceName + baseTunDeviceOutput + strconv.Itoa(i+1)
		ipaddress := tunIPAddressSubnetOut + strconv.Itoa(i+1)

		uid := 0
		gid := 0
		if user, err := user.Current(); err == nil {
			uid, _ = strconv.Atoi(user.Uid)
			gid, _ = strconv.Atoi(user.Gid)
		}
		//mac address not required for tun as of now
		if tun, err := tuntap.NewTun(maxNumQueues, ipaddress, []byte{}, deviceName, uint(uid), uint(gid), false, appQueueCallBack); err == nil {
			t.tundeviceHdls[i] = tun
			//Program TC Rules
			tcBatch, err := tcbatch.NewTCBatch(maxNumQueues-1, deviceName, 1, cgnetcls.Initialmarkval)
			if err != nil {
				zap.L().Fatal("Unable to setup queuing policy", zap.Error(err))
			}
			if err = tcBatch.BuildOutputTCBatchCommand(); err != nil {
				zap.L().Fatal("Unable to create queuing policy", zap.Error(err))
			}
			//zap.L().Error("TC Command::" + tcBatch.String())
			if err = tcBatch.Execute(); err != nil {
				zap.L().Fatal("Unable to install queuing policy", zap.Error(err))
			}

			// StartQueue here afteer we have create device and setup tc queueing.
			// Once we setup routes we can get traffic
			for qIndex := 0; qIndex < maxNumQueues; qIndex++ {
				//go rawloop(qIndex, tun, "application")
				pData := &privateData{
					t:        t,
					queueNum: qIndex,
				}
				if writer, err := afinetrawsocket.CreateSocket(dummyIPAddress, afinetrawsocket.ApplicationRawSocketMark, "tun-in1"); err == nil {
					pData.writer = writer
					go tun.StartQueue(qIndex, pData)
					continue
				}
				zap.L().Fatal("Cannot bring up write path for tun interface", zap.Error(err))
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

			if err := t.iprouteHdl.AddRoute(route); err != nil {
				// We are initing here refuse to start if this fails
				zap.L().Fatal("Unable to add ip route", zap.Error(err), zap.String("IP Address", net.ParseIP(ipaddress).String()), zap.Int("Table", NetworkRuleTable), zap.Int("Interface Index", intf.Index))

			}
		} else {
			zap.L().Fatal("Received error while creating device ", zap.Error(err), zap.String("DeviceName", deviceName))
		}

	}

}
