// +build linux

package tundatapath

import (
	"context"
	"net"
	"os/user"
	"strconv"

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
}

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
		if tun, err := tuntap.NewTun(maxNumQueues, ipaddress, []byte{}, deviceName, uint(uid), uint(gid), false); err == nil {
			t.tundeviceHdls[i] = tun
		} else {
			zap.L().Fatal("Received error while creating device ", zap.Error(err), zap.String("DeviceName", deviceName))
		}

		go func(ctx context.Context, t *tundev, k int) {
			data := make([]byte, 75*1024)
			for {
				if queues, err := t.tundeviceHdls[k].PollRead(20); err == nil {
					//We have data to Read from queues
					//propagate queue in p.mark
					for _, queue := range queues {
						if n, err := t.tundeviceHdls[k].ReadQueue(queue, data); err == nil {
							if packet, err := packet.New(packet.PacketTypeNetwork, data[:n], strconv.Itoa(queue+cgnetcls.Initialmarkval)); err == nil {
								t.processor.ProcessNetworkPacket(packet)
							} else {
								zap.L().Debug("Failed to create packet")
							}
						}
					}

				}
				select {
				case <-ctx.Done():

					return
				}

			}
		}(ctx, t, i)

		// Program Route in the tables
		intf, err := net.InterfaceByName(deviceName)
		if err != nil {
			zap.L().Fatal("Failed to retrieve device ", zap.String("DeviceName", deviceName))
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
		if tun, err := tuntap.NewTun(maxNumQueues, ipaddress, []byte{}, deviceName, uint(uid), uint(gid), false); err == nil {
			t.tundeviceHdls[i] = tun
		} else {
			zap.L().Fatal("Received error while creating device ", zap.Error(err), zap.String("DeviceName", deviceName))
		}

		go func(ctx context.Context, t *tundev, k int) {
			data := make([]byte, 75*1024)
			for {
				if queues, err := t.tundeviceHdls[k].PollRead(20); err == nil {
					//We have data to Read from queues
					//propagate queue in p.mark

					for _, queue := range queues {
						if n, err := t.tundeviceHdls[k].ReadQueue(queue, data); err == nil {
							if packet, err := packet.New(packet.PacketTypeNetwork, data[:n], strconv.Itoa(queue+cgnetcls.Initialmarkval)); err == nil {
								t.processor.ProcessApplicationPacket(packet)
							} else {
								zap.L().Debug("Failed to create packet")
							}
						}
					}

				}
				select {
				case <-ctx.Done():
					return
				}

			}
		}(ctx, t, i)
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

	}

}
