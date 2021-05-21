// +build !windows

package iptablesctrl

import (
	"fmt"
	"strconv"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	markconstants "go.aporeto.io/enforcerd/trireme-lib/utils/constants"
	"go.uber.org/zap"
)

// discoverCnsAgentBootPID is only used in Windows rules
var discoverCnsAgentBootPID = func() int {
	return -1
}

// addContainerChain adds a chain for the specific container and redirects traffic there
// This simplifies significantly the management and makes the iptable rules more readable
// All rules related to a container are contained within the dedicated chain
func (i *iptables) addContainerChain(cfg *ACLInfo) error {

	appChain := cfg.AppChain
	netChain := cfg.NetChain
	if err := i.impl.NewChain(appPacketIPTableContext, appChain); err != nil {
		return fmt.Errorf("unable to add chain %s of context %s: %s", appChain, appPacketIPTableContext, err)
	}

	// if err := i.impl.NewChain(appProxyIPTableContext, appChain); err != nil {
	// 	return fmt.Errorf("unable to add chain %s of context %s: %s", appChain, appPacketIPTableContext, err)
	// }

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

func transformACLRules(aclRules [][]string, cfg *ACLInfo, rulesBucket *rulesInfo, isAppAcls bool) [][]string {
	// pass through on linux
	return aclRules
}

func (i *iptables) platformInit() error {
	return nil
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

	// Clean all rules with TRI- sub
	i.impl.ResetRules("TRI-") // nolint: errcheck
	// Always return nil here. No reason to block anything if cleans fail.
	return nil
}

func generateUDPACLRule() []string {
	return []string{"-m", "string", "!", "--string", packet.UDPAuthMarker, "--algo", "bm", "--to", "128"}
}

func targetUDPNetworkClause(rule *aclIPset, targetUDPName string, ipMatchDirection string) []string {
	return []string{"-m", "set", "!", "--match-set", targetUDPName, ipMatchDirection}
}

func connmarkUDPConnmarkClause() []string {
	return []string{"-j", "CONNMARK", "--set-mark", strconv.Itoa(int(markconstants.DefaultExternalConnMark))}
}
