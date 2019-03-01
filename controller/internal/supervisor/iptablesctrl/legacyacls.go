package iptablesctrl

// legacyProxyRules creates all the proxy specific rules.
import "fmt"

func (i *Instance) legacyProxyRules(tcpPorts string, proxyPort string, proxyPortSetName string, cgroupMark string) [][]string {
	destSetName, srvSetName := i.getSetNames(proxyPortSetName)
	proxyrules := [][]string{
		{
			i.appProxyIPTableContext,
			natProxyInputChain,
			"-p", tcpProto,
			"-m", "set",
			"--match-set", srvSetName, "dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		},
		{
			i.netPacketIPTableContext,
			proxyInputChain,
			"-p", tcpProto,
			"-m", "set",
			"--match-set", destSetName, "src,src",
			"-j", "ACCEPT",
		},
		{ // Needed for Web sockets
			i.netPacketIPTableContext,
			proxyInputChain,
			"-p", tcpProto,
			"-m", "set",
			"--match-set", srvSetName, "dst",
			"-j", "ACCEPT",
		},
		{ // APIServices
			i.netPacketIPTableContext,
			proxyInputChain,
			"-p", tcpProto,
			"-m", "set",
			"--match-set", srvSetName, "src",
			"-m", "addrtype", "--src-type", "LOCAL",
			"-j", "ACCEPT",
		},
		{ // APIServices
			i.appPacketIPTableContext,
			proxyInputChain,
			"-p", tcpProto,
			"--destination-port", proxyPort,
			"-j", "ACCEPT",
		},
		{ // APIServices
			i.appPacketIPTableContext,
			proxyOutputChain,
			"-p", tcpProto,
			"--source-port", proxyPort,
			"-j", "ACCEPT",
		},
		{ // APIServices
			i.appPacketIPTableContext,
			proxyOutputChain,
			"-p", tcpProto,
			"-m", "set",
			"--match-set", srvSetName, "src",
			"-j", "ACCEPT",
		},
		{ // Needed for websocket support
			i.appPacketIPTableContext,
			proxyOutputChain,
			"-p", tcpProto,
			"-m", "set",
			"--match-set", srvSetName, "dst",
			"-j", "ACCEPT",
		},
		{
			i.appPacketIPTableContext,
			proxyOutputChain,
			"-p", tcpProto,
			"-m", "set",
			"--match-set", destSetName, "dst,dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "ACCEPT",
		},
	}

	if cgroupMark == "" {
		proxyrules = append(proxyrules, []string{
			i.appProxyIPTableContext,
			natProxyOutputChain,
			"-p", tcpProto,
			"-m", "set", "--match-set", destSetName, "dst,dst",
			"-m", "mark", "!", "--mark", proxyMark,
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		})
	} else {
		proxyrules = append(proxyrules, []string{
			i.appProxyIPTableContext,
			natProxyOutputChain,
			"-p", tcpProto,
			"-m", "set", "--match-set", destSetName, "dst,dst",
			"-m", "mark", "!", "--mark", proxyMark,
			"-m", "multiport",
			"--source-ports", tcpPorts,
			"-j", "REDIRECT",
			"--to-port", proxyPort,
		})
	}

	return proxyrules
}

func (i *Instance) addLegacyNATExclusionACLs(cgroupMark, setName string, exclusions []string, tcpPorts string) error {
	destSetName, srvSetName := i.getSetNames(setName)
	for _, e := range exclusions {

		if err := i.ipt.Insert(
			i.appProxyIPTableContext, natProxyInputChain, 1,
			"-p", tcpProto,
			"-m", "set",
			"-s", e,
			"--match-set", srvSetName, "dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("unable to add exclusion NAT ACL for table %s chain %s", i.appProxyIPTableContext, natProxyInputChain)
		}

		if cgroupMark == "" {
			if err := i.ipt.Insert(
				i.appProxyIPTableContext, natProxyOutputChain, 1,
				"-p", tcpProto,
				"-m", "set", "--match-set", destSetName, "dst,dst",
				"-m", "mark", "!", "--mark", proxyMark,
				"-s", e,
				"-j", "ACCEPT",
			); err != nil {
				return fmt.Errorf("unable to add exclusion rule for table %s , chain %s", i.appProxyIPTableContext, natProxyOutputChain)
			}
		} else {
			if err := i.ipt.Insert(
				i.appProxyIPTableContext, natProxyOutputChain, 1,
				"-p", tcpProto,
				"-m", "set", "--match-set", destSetName, "dst,dst",
				"-m", "mark", "!", "--mark", proxyMark,
				"-m", "multiport",
				"--source-ports", tcpPorts,
				"-s", e,
				"-j", "ACCEPT",
			); err != nil {
				return fmt.Errorf("unable to add exclusion rule for table %s , chain %s", i.appProxyIPTableContext, natProxyOutputChain)
			}
		}
	}

	return nil
}

// addExclusionACLs adds the set of IP addresses that must be excluded
func (i *Instance) deleteLegacyNATExclusionACLs(cgroupMark, setName string, exclusions []string, tcpPorts string) error {

	destSetName, srvSetName := i.getSetNames(setName)
	for _, e := range exclusions {
		if err := i.ipt.Delete(
			i.appProxyIPTableContext, natProxyInputChain,
			"-p", tcpProto,
			"-m", "set",
			"-s", e,
			"--match-set", srvSetName, "dst",
			"-m", "mark", "!",
			"--mark", proxyMark,
			"-j", "ACCEPT",
		); err != nil {
			return fmt.Errorf("unable to add exclusion NAT ACL for table %s chain %s: %s", i.appProxyIPTableContext, natProxyInputChain, err)
		}
		if cgroupMark == "" {
			if err := i.ipt.Delete(
				i.appProxyIPTableContext, natProxyOutputChain,
				"-p", tcpProto,
				"-m", "set", "--match-set", destSetName, "dst,dst",
				"-m", "mark", "!", "--mark", proxyMark,
				"-s", e,
				"-j", "ACCEPT",
			); err != nil {
				return fmt.Errorf("unable to add exclusion rule for table %s , chain %s: %s", i.appProxyIPTableContext, natProxyOutputChain, err)
			}
		} else {
			if err := i.ipt.Delete(
				i.appProxyIPTableContext, natProxyOutputChain,
				"-p", tcpProto,
				"-m", "set", "--match-set", destSetName, "dst,dst",
				"-m", "mark", "!", "--mark", proxyMark,
				"-m", "multiport",
				"--source-ports", tcpPorts,
				"-s", e,
				"-j", "ACCEPT",
			); err != nil {
				return fmt.Errorf("unable to add exclusion rule for table %s , chain %s: %s", i.appProxyIPTableContext, natProxyOutputChain, err)
			}
		}
	}

	return nil
}
