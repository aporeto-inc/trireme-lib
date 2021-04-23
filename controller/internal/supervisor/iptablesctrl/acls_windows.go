// +build windows

package iptablesctrl

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/kballard/go-shellquote"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	winipt "go.aporeto.io/enforcerd/trireme-lib/controller/internal/windows"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"

	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.uber.org/zap"
)

// discoverCnsAgentBootPID finds parent's parent pid on Windows.
// needs to happen early, in case our mgr parent is relaunched.
var discoverCnsAgentBootPID = func() int {
	pppid, err := getGrandparentPid()
	if err != nil {
		zap.L().Error("Could not get CnsAgentBootPID", zap.Error(err))
		return -1
	}
	return pppid
}

func getGrandparentPid() (int, error) {
	ppid := os.Getppid()
	if ppid <= 0 {
		return -1, fmt.Errorf("getGrandparentPid failed to get ppid")
	}
	// from getProcessEntry in syscall_windows.go
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return -1, err
	}
	defer syscall.CloseHandle(snapshot) // nolint: errcheck
	var procEntry syscall.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err = syscall.Process32First(snapshot, &procEntry); err != nil {
		return -1, err
	}
	for {
		if procEntry.ProcessID == uint32(ppid) {
			return int(procEntry.ParentProcessID), nil
		}
		err = syscall.Process32Next(snapshot, &procEntry)
		if err != nil {
			return -1, err
		}
	}
}

func (i *iptables) aclSkipProto(proto string) bool {
	return false
}

func (i *iptables) legacyPuChainRules(cfg *ACLInfo) ([][]string, bool) {
	return nil, false
}

// create ipsets needed for Windows rules
func (i *iptables) platformInit() error {

	ipset := ipsetmanager.IPsetProvider()

	cfg, err := i.newACLInfo(0, "", nil, 0)
	if err != nil {
		return err
	}

	existingSets, err := ipset.ListIPSets()
	if err != nil {
		return err
	}

	setExists := func(s string) bool {
		for _, existing := range existingSets {
			if existing == s {
				return true
			}
		}
		return false
	}

	if !setExists("TRI-v4-WindowsAllIPs") {
		allIPsV4, err := ipset.NewIpset("TRI-v4-WindowsAllIPs", "hash:net", nil)
		if err != nil {
			return err
		}
		err = allIPsV4.Add("0.0.0.0/0", 0)
		if err != nil {
			return err
		}
	}

	if !setExists("TRI-v6-WindowsAllIPs") {
		allIPsV6, err := ipset.NewIpset("TRI-v6-WindowsAllIPs", "hash:net", nil)
		if err != nil {
			return err
		}
		err = allIPsV6.Add("::/0", 0)
		if err != nil {
			return err
		}
	}

	if cfg.DNSServerIP != "" {
		// TRI-v4-WindowsDNSServer is used in a global rule that applies to both IPv4/IPv6,
		// but we need the TRI-v4 prefix on the name so that it is properly cleaned up
		if !setExists("TRI-v4-WindowsDNSServer") {
			dnsIPSet, err := ipset.NewIpset("TRI-v4-WindowsDNSServer", "hash:net", nil)
			if err != nil {
				return err
			}
			switch cfg.DNSServerIP {
			case IPv4DefaultIP, IPv6DefaultIP:
				// in the case of an all-network range (which is the default value), we need to allow all for ipv4+ipv6
				err = dnsIPSet.Add(IPv4DefaultIP, 0)
				if err != nil {
					return err
				}
				err = dnsIPSet.Add(IPv6DefaultIP, 0)
				if err != nil {
					return err
				}
			default:
				// for now, we add
				err = dnsIPSet.Add(cfg.DNSServerIP, 0)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// addContainerChain for Windows
func (i *iptables) addContainerChain(cfg *ACLInfo) error {
	appChain := cfg.AppChain
	netChain := cfg.NetChain
	if err := i.impl.NewChain(appPacketIPTableContext, appChain); err != nil {
		return fmt.Errorf("unable to add chain %s of context %s: %s", appChain, appPacketIPTableContext, err)
	}
	if err := i.impl.NewChain(netPacketIPTableContext, netChain); err != nil {
		return fmt.Errorf("unable to add netchain %s of context %s: %s", netChain, netPacketIPTableContext, err)
	}
	return nil
}

// deletePUChains removes all the container specific chains and basic rules
func (i *iptables) deletePUChains(cfg *ACLInfo) error {

	if err := i.impl.ClearChain(appPacketIPTableContext, cfg.AppChain); err != nil {
		zap.L().Warn("Failed to clear the container ack packets chain",
			zap.String("appChain", cfg.AppChain),
			zap.String("context", appPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.impl.DeleteChain(appPacketIPTableContext, cfg.AppChain); err != nil {
		zap.L().Warn("Failed to delete the container ack packets chain",
			zap.String("appChain", cfg.AppChain),
			zap.String("context", appPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.impl.ClearChain(netPacketIPTableContext, cfg.NetChain); err != nil {
		zap.L().Warn("Failed to clear the container net packets chain",
			zap.String("netChain", cfg.NetChain),
			zap.String("context", netPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.impl.DeleteChain(netPacketIPTableContext, cfg.NetChain); err != nil {
		zap.L().Warn("Failed to delete the container net packets chain",
			zap.String("netChain", cfg.NetChain),
			zap.String("context", netPacketIPTableContext),
			zap.Error(err),
		)
	}

	return nil
}

// try to merge two acl rules (one log and one accept/drop) into one for Windows
func makeTerminatingRuleFromPair(aclRule1, aclRule2 []string) *winipt.WindowsRuleSpec {

	if aclRule1 == nil || aclRule2 == nil {
		return nil
	}
	winRuleSpec1, err := winipt.ParseRuleSpec(aclRule1[2:]...)
	if err != nil {
		return nil
	}
	winRuleSpec2, err := winipt.ParseRuleSpec(aclRule2[2:]...)
	if err != nil {
		return nil
	}

	// save action/log properties, as long as one rule is an action and the other is nflog
	action := 0
	logPrefix := ""
	groupID := 0
	if action == 0 && winRuleSpec1.Action != 0 && winRuleSpec2.Log {
		action = winRuleSpec1.Action
		logPrefix = winRuleSpec2.LogPrefix
		groupID = winRuleSpec2.GroupID
	}
	if action == 0 && winRuleSpec2.Action != 0 && winRuleSpec1.Log {
		action = winRuleSpec2.Action
		logPrefix = winRuleSpec1.LogPrefix
		groupID = winRuleSpec1.GroupID
	}
	if action == 0 {
		return nil
	}

	// if one is nflog and one is another action, and they are otherwise equal, then combine into one rule
	winRuleSpec1.Log = false
	winRuleSpec1.LogPrefix = ""
	winRuleSpec1.GroupID = 0
	winRuleSpec1.Action = 0
	winRuleSpec2.Log = false
	winRuleSpec2.LogPrefix = ""
	winRuleSpec2.GroupID = 0
	winRuleSpec2.Action = 0
	if winRuleSpec1.Equal(winRuleSpec2) {
		winRuleSpec1.Log = true
		winRuleSpec1.LogPrefix = logPrefix
		winRuleSpec1.GroupID = groupID
		winRuleSpec1.Action = action
		return winRuleSpec1
	}
	return nil
}

// take a parsed acl rule and clean it up, returning an acl rule in []string format
func processWindowsACLRule(table, _ string, winRuleSpec *winipt.WindowsRuleSpec, cfg *ACLInfo, isAppAcls bool) ([]string, error) {
	var chain string
	if isAppAcls {
		chain = cfg.AppChain
	} else {
		chain = cfg.NetChain
	}
	switch cfg.PUType {
	case common.HostPU:
	case common.HostNetworkPU:
		if isAppAcls {
			return nil, nil
		}
		switch winRuleSpec.Protocol {
		case packet.IPProtocolTCP:
		case packet.IPProtocolUDP:
		default:
			return nil, nil
		}
	case common.WindowsProcessPU:
	default:
		return nil, fmt.Errorf("unexpected Windows PU: %v", cfg.PUType)
	}
	rulespec, _ := winipt.MakeRuleSpecText(winRuleSpec, false)

	rule, err := shellquote.Split(rulespec)
	if err != nil {
		return nil, err
	}

	return append([]string{table, chain}, rule...), nil
}

// while not strictly necessary now for Windows, we still try to combine a log (non-terminating rule) and another terminating rule.
func transformACLRules(aclRules [][]string, cfg *ACLInfo, rulesBucket *rulesInfo, isAppAcls bool) [][]string {

	// find the reverse rules and remove them.
	// note: we assume that reverse rules are the ones we add for UDP established reverse flows.
	// we handle this in the windows driver so we don't need a rule for it.
	// again: our driver assumes that all UDP acl rules will have a reverse flow added.
	if rulesBucket != nil {
		for _, rr := range rulesBucket.ReverseRules {
			revTable, revChain := rr[0], rr[1]
			revRule, err := winipt.ParseRuleSpec(rr[2:]...)
			if err != nil {
				zap.L().Error("transformACLRules failed to parse reverse rule", zap.Error(err))
				continue
			}
			found := false
			for i, r := range aclRules {
				rule, err := winipt.ParseRuleSpec(r[2:]...)
				if err != nil {
					zap.L().Error("transformACLRules failed to parse rule", zap.Error(err))
					continue
				}
				table, chain := r[0], r[1]
				if table == revTable && chain == revChain && rule.Equal(revRule) {
					found = true
					aclRules = append(aclRules[:i], aclRules[i+1:]...)
					break
				}
			}
			if !found {
				zap.L().Warn("transformACLRules could not find reverse rule")
			}
		}
	}

	var result [][]string

	// now in the loop, compare successive rules to see if they are equal, disregarding their action or log properties.
	// if they are, then combine them into one rule.
	var aclRule1, aclRule2 []string
	for i := 0; i < len(aclRules) || aclRule1 != nil; i++ {
		if aclRule1 == nil {
			aclRule1 = aclRules[i]
			i++
		}
		if i < len(aclRules) {
			aclRule2 = aclRules[i]
		}
		table, chain := aclRule1[0], aclRule1[1]
		winRule := makeTerminatingRuleFromPair(aclRule1, aclRule2)
		if winRule == nil {
			// not combinable, so work on rule 1
			var err error
			winRule, err = winipt.ParseRuleSpec(aclRule1[2:]...)
			aclRule1 = aclRule2
			aclRule2 = nil
			if err != nil {
				zap.L().Error("transformACLRules failed", zap.Error(err))
				continue
			}
		} else {
			aclRule1 = nil
			aclRule2 = nil
		}
		// process rule
		xformedRule, err := processWindowsACLRule(table, chain, winRule, cfg, isAppAcls)
		if err != nil {
			zap.L().Error("transformACLRules failed", zap.Error(err))
			continue
		}
		if xformedRule != nil {
			result = append(result, xformedRule)
		}
	}

	if result == nil {
		result = [][]string{}
	}
	return result
}

func (i *iptables) cleanACLs() error { // nolint
	cfg, err := i.newACLInfo(0, "", nil, 0)
	if err != nil {
		return err
	}

	// First clear the nat rules
	if err := i.removeGlobalHooks(cfg); err != nil {
		zap.L().Error("unable to remove nat proxy rules")
	}

	// Clean Application Rules/Chains
	i.cleanACLSection(appPacketIPTableContext, constants.ChainPrefix)
	i.cleanACLSection(appProxyIPTableContext, constants.ChainPrefix)

	i.impl.Commit() // nolint

	// Always return nil here. No reason to block anything if cleans fail.
	return nil
}

// cleanACLSection flushes and deletes all chains with Prefix - Trireme
func (i *iptables) cleanACLSection(context, chainPrefix string) {

	rules, err := i.impl.ListChains(context)
	if err != nil {
		zap.L().Warn("Failed to list chains",
			zap.String("context", context),
			zap.Error(err),
		)
	}

	for _, rule := range rules {
		if strings.Contains(rule, chainPrefix) {
			if err := i.impl.ClearChain(context, rule); err != nil {
				zap.L().Warn("Can not clear the chain",
					zap.String("context", context),
					zap.String("section", rule),
					zap.Error(err),
				)
			}
		}
	}

	for _, rule := range rules {
		if strings.Contains(rule, chainPrefix) {
			if err := i.impl.DeleteChain(context, rule); err != nil {
				zap.L().Warn("Can not delete the chain",
					zap.String("context", context),
					zap.String("section", rule),
					zap.Error(err),
				)
			}
		}
	}
}

func generateUDPACLRule() []string {
	//-m", "string", "!", "--string", packet.UDPAuthMarker, "--offset", "4"
	return []string{"-m", "string", "--string", "!", packet.UDPAuthMarker, "--offset", "6"}
}

func targetUDPNetworkClause(rule *aclIPset, targetUDPName string, ipMatchDirection string) []string {
	if !strings.Contains(strings.Join(rule.Ports, ","), "53") {
		return []string{"-m", "set", "!", "--match-set", targetUDPName, ipMatchDirection}
	}
	return []string{}
}

func connmarkUDPConnmarkClause() []string {
	return []string{}
}
