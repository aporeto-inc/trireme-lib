package iptablesctrl

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"text/template"

	"github.com/aporeto-inc/go-ipset/ipset"
	"github.com/spaolacci/murmur3"
	"go.aporeto.io/trireme-lib/buildflags"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cache"
	markconstants "go.aporeto.io/trireme-lib/utils/constants"
	"go.uber.org/zap"
)

const (
	chainPrefix         = "TRI-"
	mainAppChain        = chainPrefix + "App"
	mainNetChain        = chainPrefix + "Net"
	uidchain            = chainPrefix + "UID-App"
	uidInput            = chainPrefix + "UID-Net"
	appChainPrefix      = chainPrefix + "App-"
	netChainPrefix      = chainPrefix + "Net-"
	natProxyOutputChain = chainPrefix + "Redir-App"
	natProxyInputChain  = chainPrefix + "Redir-Net"
	proxyOutputChain    = chainPrefix + "Prx-App"
	proxyInputChain     = chainPrefix + "Prx-Net"

	targetTCPNetworkSet  = "TargetTCP"
	targetUDPNetworkSet  = "TargetUDP"
	excludedNetworkSet   = "Excluded"
	uidPortSetPrefix     = "UID-Port-"
	processPortSetPrefix = "ProcPort-"
	proxyPortSetPrefix   = "Proxy-"
	// TriremeInput represent the chain that contains pu input rules.
	TriremeInput = chainPrefix + "Pid-Net"
	// TriremeOutput represent the chain that contains pu output rules.
	TriremeOutput = chainPrefix + "Pid-App"

	// NetworkSvcInput represent the chain that contains NetworkSvc input rules.
	NetworkSvcInput = chainPrefix + "Svc-Net"

	// NetworkSvcOutput represent the chain that contains NetworkSvc output rules.
	NetworkSvcOutput = chainPrefix + "Svc-App"

	// HostModeInput represent the chain that contains Hostmode input rules.
	HostModeInput = chainPrefix + "Hst-Net"

	// HostModeOutput represent the chain that contains Hostmode output rules.
	HostModeOutput = chainPrefix + "Hst-App"

	ipTableSectionOutput     = "OUTPUT"
	ipTableSectionPreRouting = "PREROUTING"
	appPacketIPTableContext  = "mangle"
	netPacketIPTableContext  = "mangle"
	appProxyIPTableContext   = "nat"

	proxyMark = "0x40"
)

type iptables struct {
	impl                  IPImpl
	fqc                   *fqconfig.FilterQueue
	mode                  constants.ModeType
	isLegacyKernel        bool
	conntrackCmd          func([]string)
	ipset                 provider.IpsetProvider
	targetTCPSet          provider.Ipset
	targetUDPSet          provider.Ipset
	excludedNetworksSet   provider.Ipset
	cfg                   *runtime.Configuration
	contextIDToPortSetMap cache.DataStore
	aclmanager            ipsetmanager.ACLManager
}

// IPImpl interface is to be used by the iptable implentors like ipv4 and ipv6.
type IPImpl interface {
	provider.IptablesProvider
	GetIPSetPrefix() string
	IPsetVersion() int
	GetIPSetParam() *ipset.Params
	ProtocolAllowed(proto string) bool
	IPFilter() func(net.IP) bool
	GetDefaultIP() string
	NeedICMP() bool
}

type ipFilter func(net.IP) bool

func filterNetworks(c *runtime.Configuration, filter ipFilter) *runtime.Configuration {
	filterIPs := func(ips []string) []string {
		var filteredIPs []string

		for _, ip := range ips {
			netIP := net.ParseIP(ip)
			if netIP == nil {
				netIP, _, _ = net.ParseCIDR(ip)
			}

			if filter(netIP) {
				filteredIPs = append(filteredIPs, ip)
			}
		}

		return filteredIPs
	}

	return &runtime.Configuration{
		TCPTargetNetworks: filterIPs(c.TCPTargetNetworks),
		UDPTargetNetworks: filterIPs(c.UDPTargetNetworks),
		ExcludedNetworks:  filterIPs(c.ExcludedNetworks),
	}
}

func createIPInstance(impl IPImpl, ips provider.IpsetProvider, fqc *fqconfig.FilterQueue, mode constants.ModeType, aclmanager ipsetmanager.ACLManager) *iptables {

	return &iptables{
		impl:                  impl,
		fqc:                   fqc,
		mode:                  mode,
		ipset:                 ips,
		isLegacyKernel:        buildflags.IsLegacyKernel(),
		conntrackCmd:          flushUDPConntrack,
		cfg:                   nil,
		contextIDToPortSetMap: cache.NewCache("contextIDToPortSetMap"),
		aclmanager:            aclmanager,
	}
}

func (i *iptables) SetTargetNetworks(c *runtime.Configuration) error {
	if c == nil {
		return nil
	}

	// If there are no target networks, capture all traffic
	if len(c.TCPTargetNetworks) == 0 {
		c.TCPTargetNetworks = []string{IPv4DefaultIP, IPv6DefaultIP}
	}
	cfg := filterNetworks(c, i.impl.IPFilter())
	var oldConfig *runtime.Configuration

	if i.cfg == nil {
		oldConfig = &runtime.Configuration{}
	} else {
		oldConfig = i.cfg.DeepCopy()
	}

	if err := i.updateAllTargetNetworks(cfg, oldConfig); err != nil {
		return err
	}

	i.cfg = cfg
	return nil
}

func (i *iptables) Run(ctx context.Context) error {

	go func() {
		<-ctx.Done()
		zap.L().Debug("Cleaning the iptable rules")
		i.CleanUp() // nolint
	}()

	// Clean any previous ACLs. This is needed in case we crashed at some
	// earlier point or there are other ACLs that create conflicts. We
	// try to clean only ACLs related to Trireme.
	if err := i.cleanACLs(); err != nil {
		return fmt.Errorf("Unable to clean previous acls while starting the supervisor: %s", err)
	}

	// Create all the basic target sets. These are the global target sets
	// that do not depend on policy configuration. If they already exist
	// we will delete them and start again.
	targetTCPSet, targetUDPSet, excludedSet, err := createGlobalSets(i.impl.GetIPSetPrefix(), i.ipset, i.impl.GetIPSetParam())
	if err != nil {
		return fmt.Errorf("unable to create global sets: %s", err)
	}

	i.targetTCPSet = targetTCPSet
	i.targetUDPSet = targetUDPSet
	i.excludedNetworksSet = excludedSet

	// Initialize all the global Trireme chains. There are several global chaims
	// that apply to all PUs:
	// Tri-App/Tri-Net are the main chains for the egress/ingress directions
	// UID related chains for any UID PUs.
	// Host, Service, Pid chains for the different modes of operation (host mode, pu mode, host service).
	// The priority is explicit (Pid activations take precedence of Service activations and Host Services)
	if err := i.initializeChains(); err != nil {
		return fmt.Errorf("Unable to initialize chains: %s", err)
	}

	// Insert the global ACLS. These are the main ACLs that will direct traffic from
	// the INPUT/OUTPUT chains to the Trireme chains. They also includes the main
	// rules of the main chains. These rules are never touched again, unless
	// if we gracefully terminate.
	if err := i.setGlobalRules(); err != nil {
		return fmt.Errorf("failed to update synack networks: %s", err)
	}

	if err := i.impl.Commit(); err != nil {
		return err
	}

	return nil
}

func (i *iptables) ConfigureRules(version int, contextID string, pu *policy.PUInfo) error {

	var err error
	var cfg *ACLInfo

	// First we create an IPSet for destination matching ports. This only
	// applies to Linux type PUs. A port set is associated with every PU,
	// and packets matching this destination get associated with the context
	// of the PU.
	if err = i.createPortSet(contextID, pu.Runtime.Options().UserID); err != nil {
		return err
	}

	// We create the generic ACL object that is used for all the templates.
	cfg, err = i.newACLInfo(version, contextID, pu, pu.Runtime.PUType())
	if err != nil {
		return err
	}

	// Create the proxy sets. These are the target sets that will match
	// traffic towards the L4 and L4 services. There are two sets created
	// for every PU in this context (for outgoing and incoming traffic).
	// The outgoing sets capture all traffic towards specific destinations
	// as proxied traffic. Incoming sets correspond to the listening
	// services.
	if err = i.createProxySets(cfg.ProxySetName); err != nil {
		return err
	}

	// At this point we can install all the ACL rules that will direct
	// traffic to user space, allow for external access or direct
	// traffic towards the proxies
	if err = i.installRules(cfg, pu); err != nil {
		return err
	}

	// We commit the ACLs at the end. Note, that some of the ACLs in the
	// NAT table are not committed as a group. The commit function only
	// applies when newer versions of tables are installed (1.6.2 and above).
	if err = i.impl.Commit(); err != nil {
		zap.L().Error("unable to configure rules", zap.Error(err))
		return err
	}

	i.conntrackCmd(i.cfg.UDPTargetNetworks)
	return nil
}

func (i *iptables) DeleteRules(version int, contextID string, tcpPorts, udpPorts string, mark string, username string, proxyPort string, dnsProxyPort string, puType common.PUType) error {
	cfg, err := i.newACLInfo(version, contextID, nil, puType)
	if err != nil {
		zap.L().Error("unable to create cleanup configuration", zap.Error(err))
		return err
	}
	if i.mode == constants.LocalServer {
		markIntVal, err := strconv.Atoi(mark)
		if err != nil {
			zap.L().Error("mark Conversion error", zap.Error(err))
			return err
		}
		cfg.PacketMark = strconv.Itoa(markIntVal << markconstants.MarkShift)
	}
	cfg.UDPPorts = udpPorts
	cfg.TCPPorts = tcpPorts
	cfg.CgroupMark = mark
	cfg.Mark = mark

	cfg.UID = username
	cfg.PUType = puType
	cfg.ProxyPort = proxyPort
	cfg.DNSProxyPort = dnsProxyPort
	// We clean up the chain rules first, so that we can delete the chains.
	// If any rule is not deleted, then the chain will show as busy.
	if err := i.deleteChainRules(cfg); err != nil {
		zap.L().Warn("Failed to clean rules", zap.Error(err))
	}

	// We can now delete the chains we have created for this PU. Note that
	// in every case we only create two chains for every PU. All other
	// chains are global.
	if err = i.deletePUChains(cfg.AppChain, cfg.NetChain); err != nil {
		zap.L().Warn("Failed to clean container chains while deleting the rules", zap.Error(err))
	}

	// We call commit to update all the changes, before destroying the ipsets.
	// References must be deleted for ipset deletion to succeed.
	if err := i.impl.Commit(); err != nil {
		zap.L().Warn("Failed to commit ACL changes", zap.Error(err))
	}

	// We delete the set that captures all destination ports of the
	// PU. This only holds for Linux PUs.
	if err := i.deletePortSet(contextID); err != nil {
		zap.L().Warn("Failed to remove port set")
	}

	// We delete the proxy port sets that were created for this PU.
	if err := i.deleteProxySets(cfg.ProxySetName); err != nil {
		zap.L().Warn("Failed to delete proxy sets", zap.Error(err))
	}

	return nil
}

func (i *iptables) UpdateRules(version int, contextID string, containerInfo *policy.PUInfo, oldContainerInfo *policy.PUInfo) error {
	policyrules := containerInfo.Policy
	if policyrules == nil {
		return errors.New("policy rules cannot be nil")
	}

	// We cache the old config and we use it to delete the previous
	// rules. Every time we update the policy the version changes to
	// its binary complement.
	newCfg, err := i.newACLInfo(version, contextID, containerInfo, containerInfo.Runtime.PUType())
	if err != nil {
		return err
	}

	oldCfg, err := i.newACLInfo(version^1, contextID, oldContainerInfo, containerInfo.Runtime.PUType())
	if err != nil {
		return err
	}

	// Install all the new rules. The hooks to the new chains are appended
	// and do not take effect yet.
	if err := i.installRules(newCfg, containerInfo); err != nil {
		zap.L().Error("unable to install rules on update", zap.Error(err))
		return err
	}

	// Remove mapping from old chain. By removing the old hooks the new
	// hooks take priority.
	if err := i.deleteChainRules(oldCfg); err != nil {
		return err
	}

	// Delete the old chains, since there are not references any more.
	if err := i.deletePUChains(oldCfg.AppChain, oldCfg.NetChain); err != nil {
		return err
	}

	// Commit all actions in on iptables-restore function.
	if err := i.impl.Commit(); err != nil {
		return err
	}

	return nil
}

func (i *iptables) CleanUp() error {

	if err := i.cleanACLs(); err != nil {
		zap.L().Error("Failed to clean acls while stopping the supervisor", zap.Error(err))
	}

	if err := i.ipset.DestroyAll(i.impl.GetIPSetPrefix()); err != nil {
		zap.L().Error("Failed to clean up ipsets", zap.Error(err))
	}

	return nil
}

func (i *iptables) updateAllTargetNetworks(cfg, oldConfig *runtime.Configuration) error {

	if err := i.updateTargetNetworks(i.targetTCPSet, oldConfig.TCPTargetNetworks, cfg.TCPTargetNetworks); err != nil {
		return err
	}

	if err := i.updateTargetNetworks(i.targetUDPSet, oldConfig.UDPTargetNetworks, cfg.UDPTargetNetworks); err != nil {
		return err
	}

	return i.updateTargetNetworks(i.excludedNetworksSet, oldConfig.ExcludedNetworks, cfg.ExcludedNetworks)
}

// InitializeChains initializes the chains.
func (i *iptables) initializeChains() error {

	cfg, err := i.newACLInfo(0, "", nil, 0)
	if err != nil {
		return err
	}

	tmpl := template.Must(template.New(triremChains).Funcs(template.FuncMap{
		"isLocalServer": func() bool {
			return i.mode == constants.LocalServer
		},
	}).Parse(triremChains))

	rules, err := extractRulesFromTemplate(tmpl, cfg)
	if err != nil {
		return fmt.Errorf("unable to create trireme chains:%s", err)
	}

	for _, rule := range rules {
		if len(rule) != 4 {
			continue
		}
		if err := i.impl.NewChain(rule[1], rule[3]); err != nil {
			return err
		}
	}

	return nil
}

// configureContainerRules adds the chain rules for a container.
// We separate in different methods to keep track of the changes
// independently.
func (i *iptables) configureContainerRules(cfg *ACLInfo) error {
	return i.addChainRules(cfg)
}

// configureLinuxRules adds the chain rules for a linux process or a UID process.
func (i *iptables) configureLinuxRules(cfg *ACLInfo) error {

	// These checks are for rather unusal error scenarios. We should
	// never see errors here. But better safe than sorry.
	if cfg.CgroupMark == "" {
		return errors.New("no mark value found")
	}

	if cfg.TCPPortSet == "" {
		return fmt.Errorf("port set was not found for the contextID. This should not happen")
	}

	return i.addChainRules(cfg)
}

func (i *iptables) deleteProxySets(proxyPortSetName string) error { // nolint

	dstPortSetName, srvPortSetName := i.getSetNames(proxyPortSetName)
	ips := i.ipset.GetIpset(dstPortSetName)
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to destroy proxyPortSet", zap.String("SetName", dstPortSetName), zap.Error(err))
	}
	ips = i.ipset.GetIpset(srvPortSetName)
	if err := ips.Destroy(); err != nil {
		zap.L().Warn("Failed to clear proxy port set", zap.String("set name", srvPortSetName), zap.Error(err))
	}
	return nil
}

func createGlobalSets(ipsetPrefix string, ips provider.IpsetProvider, params *ipset.Params) (provider.Ipset, provider.Ipset, provider.Ipset, error) {

	var err error

	defer func() {
		if err != nil {
			ips.DestroyAll(ipsetPrefix) // nolint errcheck
		}
	}()

	targetTCPSet := ipsetPrefix + targetTCPNetworkSet
	targetUDPSet := ipsetPrefix + targetUDPNetworkSet
	excludedSet := ipsetPrefix + excludedNetworkSet

	targetSetNames := []string{targetTCPSet, targetUDPSet, excludedSet}

	targetSets := map[string]provider.Ipset{}

	existingSets, err := ips.ListIPSets()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to read current sets: %s", err)
	}

	setIndex := map[string]struct{}{}
	for _, s := range existingSets {
		setIndex[s] = struct{}{}
	}

	for _, t := range targetSetNames {
		_, ok := setIndex[t]
		createdSet, err := ips.NewIpset(t, "hash:net", params)
		if err != nil {
			if !ok {
				return nil, nil, nil, err
			}
			createdSet = ips.GetIpset(t)
		}
		if err = createdSet.Flush(); err != nil {
			return nil, nil, nil, err
		}
		targetSets[t] = createdSet
	}

	return targetSets[targetTCPSet], targetSets[targetUDPSet], targetSets[excludedSet], nil
}

type aclIPset struct {
	ipset string
	*policy.IPRule
}

func (i *iptables) getACLIPSets(ipRules policy.IPRuleList) []aclIPset {

	ipsets := i.aclmanager.GetIPsets(ipRules, i.impl.IPsetVersion())

	aclIPsets := make([]aclIPset, len(ipsets))

	for i, ipset := range ipsets {
		aclIPsets[i] = aclIPset{ipset, &ipRules[i]}
	}

	return aclIPsets
}

// Install rules will install all the rules and update the port sets.
func (i *iptables) installRules(cfg *ACLInfo, containerInfo *policy.PUInfo) error {
	policyrules := containerInfo.Policy

	if err := i.updateProxySet(containerInfo.Policy, cfg.ProxySetName); err != nil {
		return err
	}

	appACLIPset := i.getACLIPSets(policyrules.ApplicationACLs())
	netACLIPset := i.getACLIPSets(policyrules.NetworkACLs())

	// Install the PU specific chain first.
	if err := i.addContainerChain(cfg.AppChain, cfg.NetChain); err != nil {
		return err
	}

	// If its a remote and thus container, configure container rules.
	if i.mode == constants.RemoteContainer || i.mode == constants.Sidecar {
		if err := i.configureContainerRules(cfg); err != nil {
			return err
		}
	}

	// If its a Linux process configure the Linux rules.
	if i.mode == constants.LocalServer {
		if err := i.configureLinuxRules(cfg); err != nil {
			return err
		}
	}

	isHostPU := extractors.IsHostPU(containerInfo.Runtime, i.mode)

	if err := i.addExternalACLs(cfg, cfg.AppChain, cfg.NetChain, appACLIPset, true); err != nil {
		return err
	}

	if err := i.addExternalACLs(cfg, cfg.NetChain, cfg.AppChain, netACLIPset, false); err != nil {
		return err
	}

	appAnyRules, netAnyRules, err := i.getProtocolAnyRules(cfg, appACLIPset, netACLIPset)
	if err != nil {
		return err
	}

	return i.addPacketTrap(cfg, isHostPU, appAnyRules, netAnyRules)
}

// puPortSetName returns the name of the pu portset.
func puPortSetName(contextID string, prefix string) string {
	hash := murmur3.New64()

	if _, err := io.WriteString(hash, contextID); err != nil {
		return ""
	}

	output := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	if len(contextID) > 4 {
		contextID = contextID[:4] + output[:4]
	} else {
		contextID = contextID + output[:4]
	}

	if len(prefix) > 16 {
		prefix = prefix[:16]
	}

	return (prefix + contextID)
}

// flushUDPConntrack will flush the UDP conntrack table that matches our networks.
func flushUDPConntrack(networks []string) {
	// TODD: Add proper UDP connection flash for Linux processes
	// make sure that we only flush for the initiating process.
	// cmd := "conntrack"
	// for _, n := range networks {
	// 	if _, err := exec.Command(cmd, "-D", "-p", "udp", "--src", n).Output(); err != nil && err.Error() != "exit status 1" {
	// 		zap.L().Warn("Failed to remove source conntrack entries for UDP target network", zap.Error(err))
	// 	}
	// 	if _, err := exec.Command(cmd, "-D", "-p", "udp", "--dst", n).Output(); err != nil && err.Error() != "exit status 1" {
	// 		zap.L().Warn("Failed to remove destination conntrack entries for UDP target network", zap.Error(err))
	// 	}
	// }
}
