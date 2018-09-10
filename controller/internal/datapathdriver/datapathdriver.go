// +build linux

package datapathdriver

import (
	"context"
	"fmt"
	"time"

	"go.aporeto.io/netlink-go/nfqueue"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

type datapathpacketimpl struct {
	fqaccessor     filter.FilterQueueAccessor
	packetCallback func(packet []byte, ID int, mark int, d interface{})
	callbackData   interface{}
}

type datapathimpl struct {
	datapathpacketimpl
	datapathruleimpl
}

func callBack(packet nfqueue.NFPacket, callBackData interface{}) {
	hdl := callBackData.(*datapathpacketimpl)
	return hdl.packetCallback(packet.Buffer, packet.ID, packet.Mark, hdl.callbackData)
}

// New create a new instance of datapathdriver which hides the implementation details of datapath
func New(packetCallback func(packet *nfqueue.NFPacket, d interface{}), callbackData interface{}, filterQueue fqconfig.FilterQueueAccessor, mode constants.ModeType) (DatapathPacketDriver, DatapathRuleDriver, error) {
	datpath := &datapathimpl{}
	if direction == "Network" {
		datapath.numQueues = fqconfig
	}
	if err := newPacketDatpath(datpath, filterQueue, packetCallback, callbackData); err != nil {
		return nil, nil, fmt.Errorf("cannot initialize packet dapapath %s", err)
	}
	if err := newRuleDatapath(datpath, filterQueue, mode); err != nil {
		return nil, nil, fmt.Errorf("cannot initialize rule engine %s", err)
	}
	return d, d, nil
}

// NewPacketDatpath create a new os dependent packet datapath
func newPacketDatpath(hdl *datapathimpl, filterqueue fqconfig.FilterQueueAccessor, packetCallback func(packet *nfqueue.NFPacket, d interface{}), callbackData interface{}) error {

	hdl.callbackData = callbackData
	hdl.packetCallback = packetCallback
	// init low level driver in this case nfqueue do new here no init required

	return nil

}

// NewRuleDatapath create a handle for programming filtering rule
func newRuleDatapath(d *datapathimpl, filterQueue fqconfig.FilterQueueAccessor, mode constants.ModeType) (DatapathRuleDriver, error) {

}

func (d *datapathimpl) StartPacketProcessor(ctx context.Context) error {

	nfq := make([]nfqueue.Verdict, d.fqaccessor.GetNumQueues())
	for i := 0; i < d.fqaccessor.GetNumQueues(); i++ {
		nfq[i], err = nfqueue.CreateAndStartNfQueue(ctx, d.fqaccessor.GetQueueStart()+i, d.fqaccessor.GetQueueSize(), nfqueue.NfDefaultPacketSize, d.packetCallback, d.callbackData)
	}

	if err != nil {
		for retry := 0; retry < 5 && err != nil; retry++ {
			nfq[i], err = nfqueue.CreateAndStartNfQueue(ctx, d.fqaccessor.GetQueueStart()+i, d.GetQueueSize(), nfqueue.NfDefaultPacketSize, d.packetCallback, d.callbackData)
			<-time.After(3 * time.Second)
		}

		if err != nil {
			zap.L().Fatal("Unable to initialize netfilter queue", zap.Error(err))
		}
	}

	return nil
}

func (d *datapathimpl) StopPacketProcessor(ctx context.Canceled) error {
	return nil
}

// ConfigureRules configures the rules in the ACLs and datapath
func (d *datapathimpl) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {

}

// UpdateRules updates the rules with a new version
func (d *datapathimpl) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {
}

// DeleteRules
func (d *datapathimpl) DeleteRules(version int, context string, tcpPorts, udpPorts string, mark string, uid string, proxyPort string) error {
}

// SetTargetNetworks sets the target networks of the supervisor
func (d *datapathimpl) SetTargetNetworks([]string, []string) error {
}

// Start initializes any defaults
func (d *datapathimpl) Run(ctx context.Context) error {
}

// CleanUp requests the implementor to clean up all ACLs
func (d *datapathimpl) CleanUp() error {
}
