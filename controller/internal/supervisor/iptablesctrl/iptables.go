package iptablesctrl

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/controller/internal/portset"
	"github.com/aporeto-inc/trireme-lib/controller/internal/supervisor/provider"
	"github.com/aporeto-inc/trireme-lib/policy"

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
	proxyPortSet             = "Proxy-"
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
	vipTargetSet            provider.Ipset
	pipTargetSet            provider.Ipset
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

// chainPrefix returns the chain name for the specific PU
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

// PuPortSetName returns the name of the pu portset
func PuPortSetName(contextID string, mark string, prefix string) string {
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

	return (prefix + contextID + mark)
}

// ConfigureRules implmenets the ConfigureRules interface
func (i *Instance) ConfigureRules(version int, contextID string, containerInfo *policy.PUInfo) error {
	policyrules := containerInfo.Policy

	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		return err
	}

	proxyPort := containerInfo.Runtime.Options().ProxyPort
	zap.L().Debug("Configure rules", zap.String("proxyPort", proxyPort))
	proxiedServices := containerInfo.Policy.ProxiedServices()

	// Configure all the ACLs
	if err = i.addContainerChain(appChain, netChain); err != nil {
		return err
	}

	if i.mode != constants.LocalServer {
		proxyPortSetName := PuPortSetName(contextID, "", proxyPortSet)

		if err = i.createProxySets(proxiedServices.PublicIPPortPair, proxiedServices.PrivateIPPortPair, proxyPortSetName); err != nil {
			zap.L().Debug("Failed to create ProxySets", zap.Error(err))
			return fmt.Errorf("Failed to create ProxySet %s : %s", proxyPortSetName, err)
		}

		if err = i.addChainRules("", appChain, netChain, "", "", "", proxyPort, proxyPortSetName); err != nil {
			return err
		}

	} else {
		mark := containerInfo.Runtime.Options().CgroupMark
		if mark == "" {
			return errors.New("no mark value found")
		}

		port := common.ConvertServicesToPortList(containerInfo.Runtime.Options().Services)

		uid := containerInfo.Runtime.Options().UserID
		if uid != "" {

			// We are about to create a uid login pu
			// This set will be empty and we will only fill it when we find a port for it
			// The reason to use contextID here is to ensure that we don't need to talk between supervisor and enforcer to share names the id is derivable from information available in the enforcer
			portSetName := PuPortSetName(contextID, mark, PuPortSet)

			if puseterr := i.createPUPortSet(portSetName); puseterr != nil {
				return puseterr
			}

			// update the portset cache, so that it can program the portset
			if i.portSetInstance == nil {
				return errors.New("enforcer portset instance cannot be nil for host")
			}
			if err = i.portSetInstance.AddUserPortSet(uid, portSetName, mark); err != nil {
				return err
			}

		}

		portSetName := PuPortSetName(contextID, mark, PuPortSet)
		proxyPortSetName := PuPortSetName(contextID, mark, proxyPortSet)

		if err = i.createProxySets(proxiedServices.PublicIPPortPair, proxiedServices.PrivateIPPortPair, proxyPortSetName); err != nil {
			zap.L().Debug("Failed to create ProxySets", zap.Error(err))
			return fmt.Errorf("Failed to create ProxySet %s : %s", proxyPortSetName, err)
		}

		if err := i.addChainRules(portSetName, appChain, netChain, port, mark, uid, proxyPort, proxyPortSetName); err != nil {

			return err
		}
	}

	if err := i.addPacketTrap(appChain, netChain, containerInfo.Policy.TriremeNetworks()); err != nil {
		return err
	}

	if err := i.addAppACLs(contextID, appChain, policyrules.ApplicationACLs()); err != nil {
		return err
	}

	if err := i.addNetACLs(contextID, netChain, policyrules.NetworkACLs()); err != nil {
		return err
	}

	return i.addExclusionACLs(appChain, netChain, policyrules.ExcludedNetworks())
}

// DeleteRules implements the DeleteRules interface
func (i *Instance) DeleteRules(version int, contextID string, port string, mark string, uid string, proxyPort string, proxyPortSetName string) error {

	appChain, netChain, err := i.chainName(contextID, version)
	if err != nil {
		// Don't return here we can still try and reclaims portset and targetnetwork sets
		zap.L().Error("Count not generate chain name", zap.Error(err))
	}
	portSetName := PuPortSetName(contextID, mark, PuPortSet)
	if derr := i.deleteChainRules(portSetName, appChain, netChain, port, mark, uid, proxyPort, proxyPortSetName); derr != nil {
		zap.L().Warn("Failed to clean rules", zap.Error(derr))
	}

	if err = i.deleteAllContainerChains(appChain, netChain); err != nil {
		zap.L().Warn("Failed to clean container chains while deleting the rules", zap.Error(err))
	}
	if uid != "" {

		portSetName := PuPortSetName(contextID, mark, PuPortSet)

		ips := ipset.IPSet{
			Name: portSetName,
		}
		if err = ips.Destroy(); err != nil {
			zap.L().Warn("Failed to clear puport set", zap.Error(err))
		}

		// delete the entry in the portset cache
		if i.portSetInstance == nil {
			return errors.New("enforcer portset instance cannot be nil for host")
		}
		if err = i.portSetInstance.DelUserPortSet(uid, mark); err != nil {
			return err
		}
	}
	dstPortSetName, srcPortSetName := i.getSetNamePair(proxyPortSetName)
	ips := ipset.IPSet{
		Name: dstPortSetName,
	}
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to destroy proxyPortSet", zap.String("SetName", proxyPortSetName), zap.Error(err))
	}
	ips = ipset.IPSet{
		Name: srcPortSetName,
	}
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to destroy proxyPortSet", zap.String("SetName", proxyPortSetName), zap.Error(err))
	}
	return nil
}

// UpdateRules implements the update part of the interface
func (i *Instance) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {

	if containerInfo == nil {
		return errors.New("container info cannot be nil")
	}

	policyrules := containerInfo.Policy
	if policyrules == nil {
		return errors.New("policy rules cannot be nil")
	}

	proxyPort := containerInfo.Runtime.Options().ProxyPort

	appChain, netChain, err := i.chainName(contextID, version)

	if err != nil {
		return err
	}

	oldAppChain, oldNetChain, err := i.chainName(contextID, version^1)

	if err != nil {
		return err
	}

	// Add a new chain for this update and map all rules there
	if err := i.addContainerChain(appChain, netChain); err != nil {
		return err
	}

	if err := i.addPacketTrap(appChain, netChain, containerInfo.Policy.TriremeNetworks()); err != nil {
		return err
	}

	if err := i.addAppACLs(contextID, appChain, policyrules.ApplicationACLs()); err != nil {
		return err
	}

	if err := i.addNetACLs(contextID, netChain, policyrules.NetworkACLs()); err != nil {
		return err
	}

	if err := i.addExclusionACLs(appChain, netChain, policyrules.ExcludedNetworks()); err != nil {
		return err
	}

	// Add mapping to new chain
	if i.mode != constants.LocalServer {
		proxyPortSetName := PuPortSetName(contextID, "", proxyPortSet)
		if err := i.addChainRules("", appChain, netChain, "", "", "", proxyPort, proxyPortSetName); err != nil {
			return err
		}
	} else {
		mark := containerInfo.Runtime.Options().CgroupMark
		if mark == "" {
			return errors.New("no mark value found")
		}
		portlist := common.ConvertServicesToPortList(containerInfo.Runtime.Options().Services)
		uid := containerInfo.Runtime.Options().UserID

		portSetName := PuPortSetName(contextID, mark, PuPortSet)
		proxyPortSetName := PuPortSetName(contextID, mark, proxyPortSet)
		if err := i.addChainRules(portSetName, appChain, netChain, portlist, mark, uid, proxyPort, proxyPortSetName); err != nil {
			return err
		}

	}

	// Remove mapping from old chain
	if i.mode != constants.LocalServer {
		proxyPortSetName := PuPortSetName(contextID, "", proxyPortSet)
		if err := i.deleteChainRules("", oldAppChain, oldNetChain, "", "", "", proxyPort, proxyPortSetName); err != nil {

			return err
		}
	} else {
		mark := containerInfo.Runtime.Options().CgroupMark
		port := common.ConvertServicesToPortList(containerInfo.Runtime.Options().Services)
		uid := containerInfo.Runtime.Options().UserID

		portSetName := PuPortSetName(contextID, mark, PuPortSet)
		proxyPortSetName := PuPortSetName(contextID, mark, proxyPortSet)
		if err := i.deleteChainRules(portSetName, oldAppChain, oldNetChain, port, mark, uid, proxyPort, proxyPortSetName); err != nil {
			return err
		}

	}
	// Update Proxy Ports
	mark := ""
	if i.mode == constants.LocalServer {
		mark = containerInfo.Runtime.Options().CgroupMark
	}
	proxyPortSetName := PuPortSetName(contextID, mark, proxyPortSet)
	proxiedServiceList := containerInfo.Policy.ProxiedServices()
	if err := i.updateProxySet(proxiedServiceList.PublicIPPortPair, proxiedServiceList.PrivateIPPortPair, proxyPortSetName); err != nil {
		zap.L().Debug("Failed to update Proxy Set", zap.Error(err),
			zap.Strings("Public ProxiedService List", proxiedServiceList.PublicIPPortPair),
			zap.Strings("Private ProxiedService List", proxiedServiceList.PrivateIPPortPair),
		)
		return fmt.Errorf("Failed to update proxySet %s : %s", proxyPortSetName, err)
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

	go func() {
		<-ctx.Done()
		zap.L().Debug("Stop the supervisor")

		// Clean any previous ACLs that we have installed
		if err := i.cleanACLs(); err != nil {
			zap.L().Error("Failed to clean acls while stopping the supervisor", zap.Error(err))
		}

		if err := i.ipset.DestroyAll(); err != nil {
			zap.L().Error("Failed to clean up ipsets", zap.Error(err))
		}

	}()

	zap.L().Debug("Started the iptables controller")

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
	if i.mode == constants.LocalServer {
		if err := i.ipt.NewChain(i.appPacketIPTableContext, uidchain); err != nil {
			zap.L().Error("Unable to create new chain", zap.String("TableContext", i.appPacketIPTableContext), zap.String("ChainName", uidchain))
			return err
		}
	}
	if err := i.ipt.NewChain(i.appProxyIPTableContext, natProxyInputChain); err != nil {
		zap.L().Info("Unable to create New Chain", zap.String("TableContext", i.appProxyIPTableContext), zap.String("ChainName", natProxyInputChain))
	}
	zap.L().Debug("Created NewChain ", zap.String("TableContext", i.appProxyIPTableContext), zap.String("ChainName", natProxyOutputChain))
	if err := i.ipt.NewChain(i.appProxyIPTableContext, natProxyOutputChain); err != nil {
		zap.L().Info("Unable to create New Chain", zap.String("TableContext", i.appProxyIPTableContext), zap.String("ChainName", natProxyOutputChain))
	}
	zap.L().Debug("Created NewChain ", zap.String("TableContext", i.appProxyIPTableContext), zap.String("ChainName", natProxyOutputChain))
	if err := i.ipt.NewChain(i.appPacketIPTableContext, proxyOutputChain); err != nil {
		zap.L().Error("Unable to create New Chain", zap.String("TableContext", i.appPacketIPTableContext), zap.String("ChainName", proxyOutputChain))
	}
	if err := i.ipt.NewChain(i.appPacketIPTableContext, proxyInputChain); err != nil {
		zap.L().Error("Unable to create New Chain", zap.String("TableContext", i.appPacketIPTableContext), zap.String("ChainName", proxyInputChain))
	}
	if i.mode == constants.LocalServer {
		if err := i.ipt.Insert(i.appPacketIPTableContext, i.appPacketIPTableSection, 1, "-j", uidchain); err != nil {
			zap.L().Error("Unable to Insert", zap.String("TableContext", i.appPacketIPTableContext), zap.String("ChainName", uidchain))
		}
	}
	// Insert the ACLS that point to the target networks
	if err := i.setGlobalRules(i.appPacketIPTableSection, i.netPacketIPTableSection); err != nil {
		return fmt.Errorf("failed to update synack networks: %s", err)
	}

	return nil
}
