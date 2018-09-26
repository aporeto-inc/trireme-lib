package datapathdriver

import (
	"context"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/portset"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/policy"
)

// DatapathDriver top interface if the rule and packet delivery is implemented by the same mechanism
type DatapathDriver interface {
	DatapathPacketDriver
	DatapathRuleDriver
}

// DatapathRuleDriver to capture packets specified by packet filters
type DatapathRuleDriver interface {

	// InitRuleDatapath create a handle for programming filtering rule
	InitRuleDatapath(filterQueue *fqconfig.FilterQueue, mode constants.ModeType, portSetInstance portset.PortSet) error

	// ConfigureRules configures the rules in the ACLs and datapath
	ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error

	// UpdateRules updates the rules with a new version
	UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error

	// DeleteRules
	DeleteRules(version int, context string, tcpPorts, udpPorts string, mark string, uid string, proxyPort string) error

	// SetTargetNetworks sets the target networks of the supervisor
	SetTargetNetworks([]string, []string) error

	// Start initializes any defaults
	Run(ctx context.Context) error

	// CleanUp requests the implementor to clean up all ACLs
	CleanUp() error

	ACLProvider() provider.IptablesProvider
}

// DatapathPacketDriver generic interface to program rules for packet filtering
type DatapathPacketDriver interface {
	InitPacketDatpath(mode constants.ModeType) error
	StartPacketProcessor(
		ctx context.Context,
		fqaccessor fqconfig.FilterQueueAccessor,
		packetCallback func(packet *Packet, callbackData interface{}) ([]byte, error),
		errorCallback func(err error, data interface{}),
		data interface{},
	) error
	StopPacketProcessor(ctx context.Context) error
}
