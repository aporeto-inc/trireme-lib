// +build linux

package tundatapath

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"strconv"

	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapath/tun/utils/afinetrawsocket"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapath/tun/utils/iproute"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapath/tun/utils/tcbatch"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapath/tun/utils/tuntap"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/datapathimpl"
	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
	"github.com/netlink"
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
	return cbData.(*privateData).t.processNetworkPacketFromTun(data, cbData.(*privateData).queueNum, cbData.(*privateData).writer)
}

func appQueueCallBack(data []byte, cbData interface{}) error {
	return cbData.(*privateData).t.processAppPacketFromTun(data, cbData.(*privateData).queueNum, cbData.(*privateData).writer)
}

// NewTunDataPath instantiates a new tundatapath
func NewTunDataPath(processor datapathimpl.DataPathPacketHandler, markoffset int) datapathimpl.DatapathImpl {

	ipr, err := iproute.NewIpRouteHandle()
	if err != nil {
		zap.L().Error("Unable to create an iproute handle")
		return nil
	}
	return &tundev{
		processor:                 processor,
		numTunDevicesPerDirection: numTunDevicesPerDirection,
		tundeviceHdls:             make([]*tuntap.TunTap, numTunDevicesPerDirection),
		iprouteHdl:                ipr,
	}
}

func (t *tundev) processNetworkPacketFromTun(data []byte, queueNum int, writer afinetrawsocket.SocketWriter) error {
	netPacket, err := packet.New(packet.PacketTypeNetwork, data, strconv.Itoa(queueNum))
	if err != nil {
	} else if netPacket.IPProto == packet.IPProtocolTCP {
		err = t.processor.ProcessNetworkPacket(netPacket)
	} else {
		err = fmt.Errorf("invalid ip protocol: %d", netPacket.IPProto)
	}
	if err != nil {

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
	appPacket, err := packet.New(packet.PacketTypeApplication, data, strconv.Itoa(queueNum))
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
	return err
}

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (t *tundev) StartNetworkInterceptor(ctx context.Context) {
	if numTunDevicesPerDirection > 255 {
		zap.L().Fatal("Cannot create more than 255 devices per direction")
	}
	//Program ip route and ip rules
	rule := &netlink.Rule{
		Table:    NetworkRuleTable,
		Priority: RulePriority,
		Mark:     cgnetcls.Initialmarkval - 1,
		Mask:     RuleMask,
	}
	if err := t.iprouteHdl.AddRule(rule); err != nil {
		// We are initing here refuse to start if this fails
		zap.L().Fatal("Unable to add ip rule", zap.Error(err))

	}
	//Startup a cleanup routine here.
	go func() {
		//Cleanup on exit
		<-ctx.Done()
		t.iprouteHdl.DeleteRule(rule) // nolint

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
		if tun, err := tuntap.NewTun(maxNumQueues, ipaddress, []byte{}, deviceName, uint(uid), uint(gid), false, networkQueueCallBack); err == nil {
			t.tundeviceHdls[i] = tun
			// Program Route in the tables
			intf, err := net.InterfaceByName(deviceName)
			if err != nil {
				zap.L().Fatal("Failed to retrieve device ", zap.String("DeviceName", deviceName))
			}

			//Start Queues here
			for qIndex := 0; qIndex < maxNumQueues; qIndex++ {
				go tun.StartQueue(i, &privateData{
					t:        t,
					queueNum: qIndex,
				})
			}

			//Build Input TC batch command
			tcBatch, err := tcbatch.NewTCBatch(255, deviceName, 1, cgnetcls.Initialmarkval)
			if err != nil {
				zap.L().Fatal("Unable to setup queuing policy", zap.Error(err))
			}
			if err := tcBatch.BuildInputTCBatchCommand(); err != nil {
				zap.L().Fatal("Unable to setup queuing policy", zap.Error(err))
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
	rule := &netlink.Rule{
		Table:    ApplicationRuleTable,
		Priority: RulePriority,
		Mark:     cgnetcls.Initialmarkval - 2,
		Mask:     RuleMask,
	}
	if err := t.iprouteHdl.AddRule(rule); err != nil {
		// We are initing here refuse to start if this fails
		zap.L().Fatal("Unable to add ip rule", zap.Error(err))

	}
	go func() {
		//Cleanup on exit
		<-ctx.Done()
		t.iprouteHdl.DeleteRule(rule) // nolint

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
			tcBatch, err := tcbatch.NewTCBatch(255, deviceName, 1, cgnetcls.Initialmarkval)
			if err != nil {
				zap.L().Fatal("Unable to setup queuing policy", zap.Error(err))
			}
			if err = tcBatch.BuildOutputTCBatchCommand(); err != nil {
				zap.L().Fatal("Unable to create queuing policy", zap.Error(err))
			}
			if err = tcBatch.Execute(); err != nil {
				zap.L().Fatal("Unable to install queuing policy", zap.Error(err))
			}

			// StartQueue here afteer we have create device and setup tc queueing.
			// Once we setup routes we can get traffic
			for qIndex := 0; qIndex < maxNumQueues; qIndex++ {
				if writer, err := afinetrawsocket.CreateSocket(ipaddress); err == nil {
					go tun.StartQueue(i, &privateData{
						t:        t,
						queueNum: qIndex,
						writer:   writer,
					})
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
