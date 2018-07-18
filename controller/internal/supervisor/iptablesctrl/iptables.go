package iptablesctrl

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/portset"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/provider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/policy"

	"github.com/bvandewalle/go-ipset/ipset"
	"go.uber.org/zap"
)

const (
	uidchain         = "UIDCHAIN"
	chainPrefix      = "TRIREME-"
	appChainPrefix   = chainPrefix + "App-"
	netChainPrefix   = chainPrefix + "Net-"
	targetNetworkSet = "TargetNetSet"
	// PuPortSet The prefix for portset names
	PuPortSet                = "PUPort-"
	proxyPortSetPrefix       = "Proxy-"
	ipTableSectionOutput     = "OUTPUT"
	ipTableSectionInput      = "INPUT"
	ipTableSectionPreRouting = "PREROUTING"
	natProxyOutputChain      = "RedirProxy-App"
	natProxyInputChain       = "RedirProxy-Net"
	proxyOutputChain         = "Proxy-App"
	proxyInputChain          = "Proxy-Net"
	proxyMark                = "0x40"
	// ProxyPort DefaultProxyPort
	ProxyPort = "5000"
)

// Instance  is the structure holding all information about a implementation
type Instance struct {
	fqc                     *fqconfig.FilterQueue
	ipt                     provider.IptablesProvider
	ipset                   provider.IpsetProvider
	targetSet               provider.Ipset
	appPacketIPTableContext string
	appProxyIPTableContext  string
	appPacketIPTableSection string
	netPacketIPTableContext string
	netPacketIPTableSection string
	appCgroupIPTableSection string
	appSynAckIPTableSection string
	mode                    constants.ModeType
	portSetInstance         portset.PortSet
}

// NewInstance creates a new iptables controller instance
func NewInstance(fqc *fqconfig.FilterQueue, mode constants.ModeType, portset portset.PortSet) (*Instance, error) {

	ipt, err := provider.NewGoIPTablesProvider()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize iptables provider: %s", err)
	}

	ips := provider.NewGoIPsetProvider()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ipsets: %s", err)
	}

	i := &Instance{
		fqc:   fqc,
		ipt:   ipt,
		ipset: ips,
		appPacketIPTableContext: "mangle",
		netPacketIPTableContext: "mangle",
		appProxyIPTableContext:  "nat",
		mode:                    mode,
		portSetInstance:         portset,
		appPacketIPTableSection: ipTableSectionOutput,
		appCgroupIPTableSection: ipTableSectionOutput,
		netPacketIPTableSection: ipTableSectionInput,
		appSynAckIPTableSection: ipTableSectionOutput,
	}

	return i, nil

}

// chainPrefix returns the chain name for the specific PU.
func (i *Instance) chainName(contextID string, version int) (app, net string, err error) {
	hash := md5.New()

	if _, err := io.WriteString(hash, contextID); err != nil {
		return "", "", err
	}
	output := base64.URLEncoding.EncodeToString(hash.Sum(nil))
	if len(contextID) > 4 {
		contextID = contextID[:4] + string(output[:6])
	} else {
		contextID = contextID + string(output[:6])
	}

	app = appChainPrefix + contextID + "-" + strconv.Itoa(version)
	net = netChainPrefix + contextID + "-" + strconv.Itoa(version)

	return app, net, nil
}

// puPortSetName returns the name of the pu portset.
func puPortSetName(contextID string, prefix string) string {
	hash := md5.New()

	if _, err := io.WriteString(hash, contextID); err != nil {
		return ""
	}

	output := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	if len(contextID) > 4 {
		contextID = contextID[:4] + string(output[:4])
	} else {
		contextID = contextID + string(output[:4])
	}

	return (prefix + contextID)
}

// ConfigureRules implmenets the ConfigureRules interface. It will create the
// port sets and then it will call install rules to create all the ACLs for
// the given chains. PortSets are only created here. Updates will use the
// exact same logic.
func (i *Instance) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {

	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		return err
	}

	proxySetName := puPortSetName(contextID, proxyPortSetPrefix)

	// Create the proxy sets.
	if err := i.createProxySets(proxySetName); err != nil {
		return err
	}

	// Optionally create the UID set
	if err := i.createUIDSets(contextID, containerInfo); err != nil {
		return err
	}

	// Install all the rules
	return i.installRules(contextID, appChain, netChain, proxySetName, containerInfo)
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, tcpPorts, udpPorts string, mark string, uid string, proxyPort string) error {

	proxyPortSetName := puPortSetName(contextID, proxyPortSetPrefix)
	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		// Don't return here we can still try and reclaims portset and targetnetwork sets
		zap.L().Error("Count not generate chain name", zap.Error(err))
	}

	if derr := i.deleteChainRules(contextID, appChain, netChain, tcpPorts, udpPorts, mark, uid, proxyPort, proxyPortSetName); derr != nil {
		zap.L().Warn("Failed to clean rules", zap.Error(derr))
	}

	if err = i.deleteAllContainerChains(appChain, netChain); err != nil {
		zap.L().Warn("Failed to clean container chains while deleting the rules", zap.Error(err))
	}

	if uid != "" {
		if err := i.deleteUIDSets(contextID, uid, mark); err != nil {
			return err
		}
	}

	return i.deleteProxySets(proxyPortSetName)
}

// UpdateRules implements the update part of the interface. Update will call
// installrules to install the new rules and then it will delete the old rules.
func (i *Instance) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {

	policyrules := containerInfo.Policy
	if policyrules == nil {
		return errors.New("policy rules cannot be nil")
	}

	proxyPort := containerInfo.Runtime.Options().ProxyPort
	proxySetName := puPortSetName(contextID, proxyPortSetPrefix)

	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		return err
	}

	oldAppChain, oldNetChain, err := i.chainName(contextID, version^1)
	if err != nil {
		return err
	}

	// Install the new rules
	if err := i.installRules(contextID, appChain, netChain, proxySetName, containerInfo); err != nil {
		return nil
	}

	// Remove mapping from old chain
	if i.mode != constants.LocalServer {
		if err := i.deleteChainRules(contextID, oldAppChain, oldNetChain, "", "", "", "", proxyPort, proxySetName); err != nil {
			return err
		}
	} else {
		mark := containerInfo.Runtime.Options().CgroupMark
		tcpPorts, udpPorts := common.ConvertServicesToProtocolPortList(containerInfo.Runtime.Options().Services)
		uid := containerInfo.Runtime.Options().UserID

		if err := i.deleteChainRules(contextID, oldAppChain, oldNetChain, tcpPorts, udpPorts, mark, uid, proxyPort, proxySetName); err != nil {
			return err
		}
	}

	// Delete the old chain to clean up
	return i.deleteAllContainerChains(oldAppChain, oldNetChain)
}

// Run starts the iptables controller
func (i *Instance) Run(ctx context.Context) error {

	// Clean any previous ACLs
	if err := i.cleanACLs(); err != nil {
		zap.L().Warn("Unable to clean previous acls while starting the supervisor", zap.Error(err))
	}

	if err := i.InitializeChains(); err != nil {
		return fmt.Errorf("Unable to initialize chains: %s", err)
	}

	go func() {
		<-ctx.Done()
		zap.L().Debug("Stop the supervisor")

		i.CleanUp() // nolint
	}()

	zap.L().Debug("Started the iptables controller")

	return nil
}

// CleanUp requires the implementor to clean up all ACLs
func (i *Instance) CleanUp() error {

	if err := i.cleanACLs(); err != nil {
		zap.L().Error("Failed to clean acls while stopping the supervisor", zap.Error(err))
	}

	if err := i.ipset.DestroyAll(); err != nil {
		zap.L().Error("Failed to clean up ipsets", zap.Error(err))
	}

	return nil
}

// SetTargetNetworks updates ths target networks for SynAck packets
func (i *Instance) SetTargetNetworks(current, networks []string) error {

	if len(networks) == 0 {
		networks = []string{"0.0.0.0/1", "128.0.0.0/1"}
	}

	// Cleanup old ACLs
	if len(current) > 0 {
		return i.updateTargetNetworks(current, networks)
	}

	// Create the target network set
	if err := i.createTargetSet(networks); err != nil {
		return err
	}

	// Insert the ACLS that point to the target networks
	if err := i.setGlobalRules(i.appPacketIPTableSection, i.netPacketIPTableSection); err != nil {
		return fmt.Errorf("failed to update synack networks: %s", err)
	}

	return nil
}

// InitializeChains initializes the chains.
func (i *Instance) InitializeChains() error {

	if i.mode == constants.LocalServer {
		if err := i.ipt.NewChain(i.appPacketIPTableContext, uidchain); err != nil {
			return err
		}
	}

	if err := i.ipt.NewChain(i.appProxyIPTableContext, natProxyInputChain); err != nil {
		return err
	}

	if err := i.ipt.NewChain(i.appProxyIPTableContext, natProxyOutputChain); err != nil {
		return err
	}

	if err := i.ipt.NewChain(i.appPacketIPTableContext, proxyOutputChain); err != nil {
		return err
	}

	if err := i.ipt.NewChain(i.appPacketIPTableContext, proxyInputChain); err != nil {
		return err
	}

	if i.mode == constants.LocalServer {
		if err := i.ipt.Insert(i.appPacketIPTableContext, i.appPacketIPTableSection, 1, "-j", uidchain); err != nil {
			return err
		}
	}

	return nil
}

// configureContainerRule adds the chain rules for a container.
func (i *Instance) configureContainerRules(contextID, appChain, netChain, proxyPortSetName string, puInfo *policy.PUInfo) error {

	proxyPort := puInfo.Runtime.Options().ProxyPort

	return i.addChainRules("", appChain, netChain, "", "", "", "", proxyPort, proxyPortSetName)
}

// configureLinuxRules adds the chain rules for a linux process or a UID process.
func (i *Instance) configureLinuxRules(contextID, appChain, netChain, proxyPortSetName string, puInfo *policy.PUInfo) error {

	proxyPort := puInfo.Runtime.Options().ProxyPort

	mark := puInfo.Runtime.Options().CgroupMark
	if mark == "" {
		return errors.New("no mark value found")
	}

	tcpPorts, udpPorts := common.ConvertServicesToProtocolPortList(puInfo.Runtime.Options().Services)

	uid := puInfo.Runtime.Options().UserID
	portSetName := ""
	if uid != "" {
		portSetName = puPortSetName(contextID, PuPortSet)
		// update the portset cache, so that it can program the portset
		if i.portSetInstance == nil {
			return errors.New("enforcer portset instance cannot be nil for host")
		}
		if err := i.portSetInstance.AddUserPortSet(uid, portSetName, mark); err != nil {
			return err
		}
	}

	return i.addChainRules(portSetName, appChain, netChain, tcpPorts, udpPorts, mark, uid, proxyPort, proxyPortSetName)
}

func (i *Instance) deleteUIDSets(contextID, uid, mark string) error {

	portSetName := puPortSetName(contextID, PuPortSet)

	ips := ipset.IPSet{
		Name: portSetName,
	}
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to clear puport set", zap.Error(err))
	}

	// delete the entry in the portset cache
	if i.portSetInstance == nil {
		return errors.New("enforcer portset instance cannot be nil for host")
	}

	return i.portSetInstance.DelUserPortSet(uid, mark)
}

func (i *Instance) deleteProxySets(proxyPortSetName string) error {
	dstPortSetName, srcPortSetName, srvPortSetName := i.getSetNames(proxyPortSetName)
	ips := ipset.IPSet{
		Name: dstPortSetName,
	}
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to destroy proxyPortSet", zap.String("SetName", dstPortSetName), zap.Error(err))
	}
	ips = ipset.IPSet{
		Name: srcPortSetName,
	}
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to clear proxy port set", zap.String("set name", srcPortSetName), zap.Error(err))
	}
	ips = ipset.IPSet{
		Name: srvPortSetName,
	}
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to clear proxy port set", zap.String("set name", srvPortSetName), zap.Error(err))
	}
	return nil
}

// Install rules will install all the rules and update the port sets.
func (i *Instance) installRules(contextID, appChain, netChain, proxySetName string, containerInfo *policy.PUInfo) error {
	policyrules := containerInfo.Policy

	if err := i.updateProxySet(containerInfo.Policy, proxySetName); err != nil {
		return err
	}

	// Install the PU specific chain first.
	if err := i.addContainerChain(appChain, netChain); err != nil {
		return err
	}

	// If its a remote and thus container, configure container rules.
	if i.mode == constants.RemoteContainer || i.mode == constants.Sidecar {
		if err := i.configureContainerRules(contextID, appChain, netChain, proxySetName, containerInfo); err != nil {
			return err
		}
	}

	// If its a Linux process configure the Linux rules.
	if i.mode == constants.LocalServer {
		if err := i.configureLinuxRules(contextID, appChain, netChain, proxySetName, containerInfo); err != nil {
			return err
		}
	}

	if err := i.addPacketTrap(appChain, netChain, containerInfo.Policy.TriremeNetworks()); err != nil {
		return err
	}

	if err := i.addAppACLs(contextID, appChain, netChain, policyrules.ApplicationACLs()); err != nil {
		return err
	}

	if err := i.addNetACLs(contextID, appChain, netChain, policyrules.NetworkACLs()); err != nil {
		return err
	}

	return i.addExclusionACLs(appChain, netChain, policyrules.ExcludedNetworks())
}
