// +build linux

package datapathdriver

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"go.aporeto.io/netlink-go/nfqueue"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/datapathdriver/linux/iptablesctrl"
	"go.aporeto.io/trireme-lib/controller/internal/portset"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

// New create a new instance of datapathdriver which hides the implementation details of datapath
func New() (DatapathPacketDriver, DatapathRuleDriver, error) {
	datapath := &datapathimpl{}
	return datapath, datapath, nil
}

// opaque data passed to nfqueue. We use it to identify the impl instance and
// the passed pointer for handler
func nfqueueCallBack(packet *nfqueue.NFPacket, data interface{}) {
	nfqData := data.(*nfqCallbackData)
	packetData, err := nfqData.packetCallback(
		&Packet{
			packetPayload: packet.Buffer,
			mark:          packet.Mark,
			packetID:      packet.ID,
		},
		nfqData.data)
	if err != nil {
		//Drop packet
		packet.QueueHandle.SetVerdict2(uint32(
			packet.QueueHandle.QueueNum),
			0,
			uint32(packet.Mark),
			uint32(len(packet.Buffer)),
			uint32(packet.ID),
			packet.Buffer,
		)
	}
	// Send data
	packet.QueueHandle.SetVerdict2(uint32(packet.QueueHandle.QueueNum),
		1,
		uint32(packet.Mark),
		uint32(len(packetData)),
		uint32(packet.ID),
		packetData,
	)

}

// InitPacketDatpath create a new os dependent packet datapath
func (d *datapathimpl) InitPacketDatpath(mode constants.ModeType) error {

	// Make conntrack liberal for TCP

	sysctlCmd, err := exec.LookPath("sysctl")
	if err != nil {
		zap.L().Fatal("sysctl command must be installed", zap.Error(err))
	}

	cmd := exec.Command(sysctlCmd, "-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1")
	if err := cmd.Run(); err != nil {
		zap.L().Fatal("Failed to set conntrack options", zap.Error(err))
	}

	if mode == constants.LocalServer {
		cmd = exec.Command(sysctlCmd, "-w", "net.ipv4.ip_early_demux=0")
		if err := cmd.Run(); err != nil {
			zap.L().Fatal("Failed to set early demux options", zap.Error(err))
		}
	}
	return nil

}

func (d *datapathimpl) StartPacketProcessor(
	ctx context.Context,
	fqaccessor fqconfig.FilterQueueAccessor,
	packetCallback func(packet *Packet, callbackData interface{}) ([]byte, error),
	errorCallback func(err error, data interface{}),
	callbackData interface{},
) error {
	nfq := make([]nfqueue.Verdict, fqaccessor.GetNumQueues())
	var err error

	for i := uint16(0); i < fqaccessor.GetNumQueues(); i++ {
		nfq[i], err = nfqueue.CreateAndStartNfQueue(
			ctx,
			fqaccessor.GetQueueStart()+i,
			fqaccessor.GetQueueSize(),
			nfqueue.NfDefaultPacketSize,
			nfqueueCallBack,
			errorCallback,
			&nfqCallbackData{
				data:           callbackData,
				packetCallback: packetCallback,
			},
		)

		if err != nil {
			for retry := 0; retry < 5 && err != nil; retry++ {
				nfq[i], err = nfqueue.CreateAndStartNfQueue(
					ctx,
					fqaccessor.GetQueueStart()+i,
					fqaccessor.GetQueueSize(),
					nfqueue.NfDefaultPacketSize,
					nfqueueCallBack,
					errorCallback,
					&nfqCallbackData{
						data:           callbackData,
						packetCallback: packetCallback,
					},
				)
				<-time.After(3 * time.Second)
			}

			if err != nil {
				return fmt.Errorf("cannot Start packet processor for queue %d error %s", i, err)
			}
		}
	}
	return nil
}

func (d *datapathimpl) StopPacketProcessor(ctx context.Context) error {
	return nil
}

// InitRuleDatapath create a handle for programming filtering rule
func (d *datapathimpl) InitRuleDatapath(filterQueue *fqconfig.FilterQueue, mode constants.ModeType, portSetInstance portset.PortSet) error {

	impl, err := iptablesctrl.NewInstance(filterQueue, mode, portSetInstance)
	if err != nil {
		return fmt.Errorf("unable to initialize supervisor controllers: %s", err)
	}

	d.impl = impl
	return nil
}

// ConfigureRules configures the rules in the ACLs and datapath
func (d *datapathimpl) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {
	return d.impl.ConfigureRules(version, contextID, containerInfo)

}

// UpdateRules updates the rules with a new version
func (d *datapathimpl) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {
	return d.impl.UpdateRules(version, contextID, containerInfo, oldContainerInfo)
}

// DeleteRules
func (d *datapathimpl) DeleteRules(version int, context string, tcpPorts, udpPorts string, mark string, uid string, proxyPort string) error {
	return d.impl.DeleteRules(version, context, tcpPorts, udpPorts, mark, uid, proxyPort)
}

// SetTargetNetworks sets the target networks of the supervisor
func (d *datapathimpl) SetTargetNetworks(triremenetworks []string, networks []string) error {
	return d.impl.SetTargetNetworks(triremenetworks, networks)
}

// Start initializes any defaults
func (d *datapathimpl) Run(ctx context.Context) error {
	return d.impl.Run(ctx)
}

// CleanUp requests the implementor to clean up all ACLs
func (d *datapathimpl) CleanUp() error {
	return d.impl.CleanUp()
}

func (d *datapathimpl) ACLProvider() provider.IptablesProvider {
	return d.impl.ACLProvider()
}
