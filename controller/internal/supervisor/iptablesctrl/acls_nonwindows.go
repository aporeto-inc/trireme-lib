// +build !windows

package iptablesctrl

import (
	"fmt"

	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

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
func (i *iptables) deletePUChains(cfg *ACLInfo, containerInfo *policy.PUInfo) error {

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

// removeGlobalHooksPre is called before we jump into template driven rules.This is best effort
// no errors if these things fail.
func (i *iptables) removeGlobalHooksPre() {
	rules := [][]string{
		{
			"nat",
			"PREROUTING",
			"-p", "tcp",
			"-m", "addrtype",
			"--dst-type", "LOCAL",
			"-m", "set", "!", "--match-set", "TRI-Excluded", "src",
			"-j", "TRI-Redir-Net",
		},
		{
			"nat",
			"OUTPUT",
			"-m", "set", "!", "--match-set", "TRI-Excluded", "dst",
			"-j", "TRI-Redir-App",
		},
	}

	for _, rule := range rules {
		if err := i.impl.Delete(rule[0], rule[1], rule[2:]...); err != nil {
			zap.L().Debug("Error while delete rules", zap.Strings("rule", rule))
		}
	}

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
	i.impl.ResetRules("TRI-")
	// Always return nil here. No reason to block anything if cleans fail.
	return nil
}
