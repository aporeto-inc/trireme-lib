package datapathdriver

import (
	"context"

	"go.aporeto.io/trireme-lib/policy"
)

// DatapathDriver top interface if the rule and packet delivery is implemented by the same mechanism
type DatapathDriver interface {
	DatapathPacketDriver
	DatapathRuleDriver
}

// DatapathPacketDriver to capture packets specified by packet filters
type DatapathPacketDriver interface {
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
}

// DatapathRuleDriver generic interface to program rules for packet filtering
type DatapathRuleDriver interface {
	StartPacketProcessor(ctx context.Context) error
	StopPacketProcessor(ctx context.Context) error
}
