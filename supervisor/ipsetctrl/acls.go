package ipsetctrl

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/policy"
	"github.com/bvandewalle/go-ipset/ipset"
)

const (
	appChainPrefix = "TRIREME-App-"
	netChainPrefix = "TRIREME-Net-"
	allowPrefix    = "A-"
	rejectPrefix   = "R-"
)

// createACLSets creates the sets for a given PU
func (i *Instance) createACLSets(version string, set string, rules *policy.IPRuleList) error {

	allowSet, err := i.ips.NewIpset(set+allowPrefix+version, "hash:net,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err.Error())
	}

	rejectSet, err := i.ips.NewIpset(set+rejectPrefix+version, "hash:net,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err.Error())
	}

	for _, rule := range rules.Rules {
		var err error
		switch rule.Action {
		case policy.Accept:
			err = allowSet.Add(rule.Address+","+rule.Port, 0)
		case policy.Reject:
			err = rejectSet.Add(rule.Address+","+rule.Port, 0)
		default:
			continue
		}
		if err != nil {
			return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err.Error())
		}
	}

	return nil
}

// AddAppSetRule adds an ACL rule to the Set
func (i *Instance) addAppSetRules(version, setPrefix, ip string) error {

	if err := i.ipt.Insert(
		i.appAckPacketIPTableContext, i.appPacketIPTableSection, 3,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", setPrefix+rejectPrefix+version, "dst",
		"-s", ip,
		"-j", "DROP",
	); err != nil {
		zap.L().Debug("Error when adding app acl rule",
			zap.String("appAckPacketIPTableContext", i.appAckPacketIPTableContext),
			zap.Error(err),
		)
		return fmt.Errorf("Error when adding app acl rule: %s", err)

	}

	if err := i.ipt.Insert(
		i.appAckPacketIPTableContext, i.appPacketIPTableSection, 3,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", setPrefix+allowPrefix+version, "dst",
		"-s", ip,
		"-j", "ACCEPT",
	); err != nil {
		zap.L().Debug("Error when adding app acl rule",
			zap.String("appAckPacketIPTableContext", i.appAckPacketIPTableContext),
			zap.Error(err),
		)
		return fmt.Errorf("Error when adding app acl rule: %s", err)

	}

	return nil
}

// addNetSetRule
func (i *Instance) addNetSetRules(version, setPrefix, ip string) error {

	if err := i.ipt.Insert(
		i.netPacketIPTableContext, i.netPacketIPTableSection, 2,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", setPrefix+rejectPrefix+version, "src",
		"-d", ip,
		"-j", "DROP",
	); err != nil {
		zap.L().Debug("Error when adding app acl rule",
			zap.String("netPacketIPTableContext", i.netPacketIPTableContext),
			zap.Error(err),
		)
		return fmt.Errorf("Error when adding net acl rule: %s", err)
	}

	if err := i.ipt.Insert(
		i.netPacketIPTableContext, i.netPacketIPTableSection, 2,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", setPrefix+allowPrefix+version, "src",
		"-d", ip,
		"-j", "ACCEPT",
	); err != nil {
		zap.L().Debug("Error when adding app acl rule",
			zap.String("netPacketIPTableContext", i.netPacketIPTableContext),
			zap.Error(err),
		)
		return fmt.Errorf("Error when adding net acl rule: %s", err)
	}
	return nil
}

// deleteAppSetRule
func (i *Instance) deleteAppSetRules(version, setPrefix, ip string) error {

	if err := i.ipt.Delete(
		i.appAckPacketIPTableContext, i.appPacketIPTableSection,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", setPrefix+rejectPrefix+version, "dst",
		"-s", ip,
		"-j", "DROP",
	); err != nil {
		zap.L().Debug("Error when removing app acl rule",
			zap.String("appAckPacketIPTableContext", i.appAckPacketIPTableContext),
			zap.Error(err),
		)
	}

	if err := i.ipt.Delete(
		i.appAckPacketIPTableContext, i.appPacketIPTableSection,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", setPrefix+allowPrefix+version, "dst",
		"-s", ip,
		"-j", "ACCEPT",
	); err != nil {
		zap.L().Debug("Error when removing ingress app acl rule",
			zap.String("netPacketIPTableContext", i.netPacketIPTableContext),
			zap.String("chaim", i.appPacketIPTableSection),
			zap.Error(err),
		)
	}

	return nil
}

// deleteNetSetRule
func (i *Instance) deleteNetSetRules(version, setPrefix, ip string) error {

	if err := i.ipt.Delete(
		i.netPacketIPTableContext, i.netPacketIPTableSection,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", setPrefix+rejectPrefix+version, "src",
		"-d", ip,
		"-j", "DROP",
	); err != nil {
		zap.L().Debug("Error when removing ingress net acl rule",
			zap.String("netPacketIPTableContext", i.netPacketIPTableContext),
			zap.String("chaim", i.appPacketIPTableSection),
			zap.Error(err),
		)
	}

	if err := i.ipt.Delete(
		i.netPacketIPTableContext, i.netPacketIPTableSection,
		"-m", "state", "--state", "NEW",
		"-m", "set", "--match-set", setPrefix+allowPrefix+version, "src",
		"-d", ip,
		"-j", "ACCEPT",
	); err != nil {
		zap.L().Debug("ErrorError when removing ingress app acl rule",
			zap.String("netPacketIPTableContext", i.netPacketIPTableContext),
			zap.String("chaim", i.appPacketIPTableSection),
			zap.Error(err),
		)
	}
	return nil
}

//deleteSet deletes the ipset
func (i *Instance) deleteSet(set string) error {

	ipSet, err := i.ips.NewIpset(set, "hash:net,port", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for Trireme: %s", err)
	}

	return ipSet.Destroy()
}

// setupIpset sets up an ipset
func (i *Instance) setupIpset(target, container string) error {

	ips, err := i.ips.NewIpset(target, "hash:net", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Couldn't create IPSet for %s: %s", target, err)
	}

	i.targetSet = ips

	cSet, err := i.ips.NewIpset(container, "hash:ip", &ipset.Params{})
	if err != nil {
		return fmt.Errorf("Failed to create container set: %s", err)
	}

	i.containerSet = cSet

	return nil
}

// addTargetNets adds the target networks to the IPset
func (i *Instance) addTargetNets(networks []string) error {

	if i.targetSet == nil {
		return fmt.Errorf("Target set not configured")
	}

	for _, net := range networks {
		if err := i.targetSet.Add(net, 0); err != nil {
			return fmt.Errorf("Error adding ip %s to target networks IPSet: %s", net, err)
		}
	}
	return nil
}

func (i *Instance) addContainerToSet(ip string) error {

	if i.containerSet == nil {
		return fmt.Errorf("Container set is nil. Invalid operation")
	}

	if err := i.containerSet.Add(ip, 0); err != nil {
		return fmt.Errorf("Error adding ip %s to container set : %s", ip, err)
	}
	return nil
}

func (i *Instance) delContainerFromSet(ip string) error {

	if i.containerSet == nil {
		return fmt.Errorf("Container set is nil. Invalid operation")
	}

	if err := i.containerSet.Del(ip); err != nil {
		return fmt.Errorf("Error adding ip %s to container set : %s", ip, err)
	}
	return nil
}

// addIpsetOption
func (i *Instance) addIpsetOption(ip string) error {

	if i.targetSet == nil {
		return fmt.Errorf("Target set is nil. Cannot add option")
	}

	return i.targetSet.AddOption(ip, "nomatch", 0)
}

// deleteIpsetOption
func (i *Instance) deleteIpsetOption(ip string) error {

	if i.targetSet == nil {
		return fmt.Errorf("Target set is nil. Cannot remove option")
	}
	return i.targetSet.Del(ip)
}

// setupTrapRules
func (i *Instance) setupTrapRules(set string) error {

	rules := [][]string{
		// Application Syn and Syn/Ack in RAW
		{
			i.appPacketIPTableContext, i.appPacketIPTableSection,
			"-m", "set", "--match-set", set, "dst",
			"-m", "set", "--match-set", containerSet, "src",
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "NFQUEUE", "--queue-balance", i.applicationQueues,
		},

		// Application Matching Trireme SRC and DST. Established connections.
		{
			i.appAckPacketIPTableContext, i.appPacketIPTableSection,
			"-m", "set", "--match-set", containerSet, "src",
			"-m", "set", "--match-set", set, "dst",
			"-p", "tcp", "--tcp-flags", "FIN,SYN,RST,PSH,URG", "SYN",
			"-j", "ACCEPT",
		},

		// Application Matching Trireme SRC and DST. SYN, SYNACK connections.
		{
			i.appAckPacketIPTableContext, i.appPacketIPTableSection,
			"-m", "set", "--match-set", containerSet, "src",
			"-m", "set", "--match-set", set, "dst",
			"-p", "tcp", "--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", i.applicationQueues,
		},

		// Default Drop from Trireme to Network
		{
			i.appAckPacketIPTableContext, i.appPacketIPTableSection,
			"-m", "set", "--match-set", containerSet, "src",
			"-p", "tcp", "-m", "state", "--state", "NEW",
			"-j", "DROP",
		},

		// Network Matching Trireme SRC and DST.
		{
			i.netPacketIPTableContext, i.netPacketIPTableSection,
			"-m", "set", "--match-set", set, "src",
			"-m", "set", "--match-set", containerSet, "dst",
			"-p", "tcp",
			"-m", "connbytes", "--connbytes", ":3", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-j", "NFQUEUE", "--queue-balance", i.networkQueues,
		},

		// Default Drop from Network to Trireme.
		{
			i.netPacketIPTableContext, i.netPacketIPTableSection,
			"-m", "set", "--match-set", containerSet, "dst",
			"-p", "tcp", "-m", "state", "--state", "NEW",
			"-j", "DROP",
		},
	}

	for _, tr := range rules {
		if err := i.ipt.Append(tr[0], tr[1], tr[2:]...); err != nil {
			return fmt.Errorf("Failed to add initial rules for TriremeNet IPSet: %s", err)
		}
	}

	return nil
}

// cleanIPSets cleans all the ipsets
func (i *Instance) cleanIPSets() error {

	if err := i.ipt.ClearChain(i.appPacketIPTableContext, i.appPacketIPTableSection); err != nil {
		zap.L().Warn("Failed to cleanup app packet chain", zap.Error(err))
	}

	if err := i.ipt.ClearChain(i.appAckPacketIPTableContext, i.appPacketIPTableSection); err != nil {
		zap.L().Warn("Failed to cleanup ack packet chain", zap.Error(err))
	}

	if err := i.ipt.ClearChain(i.netPacketIPTableContext, i.netPacketIPTableSection); err != nil {
		zap.L().Warn("Failed to cleanup net packet chain", zap.Error(err))
	}

	return i.ips.DestroyAll()
}
