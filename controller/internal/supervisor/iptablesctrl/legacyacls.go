package iptablesctrl

// legacyProxyRules creates all the proxy specific rules.
import (
	"text/template"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

// This refers to the pu chain rules for pus in older distros like RH 6.9/Ubuntu 14.04. The rules
// consider source ports to identify packets from the process.
func (i *Instance) legacyPuChainRules(contextID, appChain string, netChain string, mark string, tcpPorts, udpPorts string, proxyPort string, proxyPortSetName string,
	appSection, netSection string, puType common.PUType) [][]string {

	iptableCgroupSection := appSection
	iptableNetSection := netSection
	rules := [][]string{}

	if tcpPorts != "0" {
		rules = append(rules, [][]string{
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", tcpProto,
				"-m", "multiport",
				"--source-ports", tcpPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", "MARK", "--set-mark", mark,
			},
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", tcpProto,
				"-m", "multiport",
				"--source-ports", tcpPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", appChain,
			},
			{
				i.netPacketIPTableContext,
				iptableNetSection,
				"-p", tcpProto,
				"-m", "multiport",
				"--destination-ports", tcpPorts,
				"-m", "comment", "--comment", "Container-specific-chain",
				"-j", netChain,
			}}...)
	}

	if udpPorts != "0" {
		rules = append(rules, [][]string{
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", udpProto,
				"-m", "multiport",
				"--source-ports", udpPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", "MARK", "--set-mark", mark,
			},
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", udpProto, "-m", "mark", "--mark", mark,
				"-m", "addrtype", "--src-type", "LOCAL",
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-m", "state", "--state", "NEW",
				"-j", "NFLOG", "--nflog-group", "10",
				"--nflog-prefix", policy.DefaultAcceptLogPrefix(contextID),
			},
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-m", "comment", "--comment", "traffic-same-pu",
				"-p", udpProto, "-m", "mark", "--mark", mark,
				"-m", "addrtype", "--src-type", "LOCAL",
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-j", "ACCEPT",
			},
			{
				i.appPacketIPTableContext,
				iptableCgroupSection,
				"-p", udpProto,
				"-m", "multiport",
				"--source-ports", udpPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", appChain,
			},
			{
				i.netPacketIPTableContext,
				iptableNetSection,
				"-m", "comment", "--comment", "traffic-same-pu",
				"-p", udpProto, "-m", "mark", "--mark", mark,
				"-m", "addrtype", "--src-type", "LOCAL",
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-j", "ACCEPT",
			},
			{
				i.netPacketIPTableContext,
				iptableNetSection,
				"-p", udpProto,
				"-m", "multiport",
				"--destination-ports", udpPorts,
				"-m", "comment", "--comment", "Container-specific-chain",
				"-j", netChain,
			}}...)
	}

	if puType == common.HostPU {
		// Add a capture all traffic rule for host pu. This traps all traffic going out
		// of the box.

		rules = append(rules, []string{
			i.appPacketIPTableContext,
			iptableCgroupSection,
			"-m", "comment", "--comment", "capture all outgoing traffic",
			"-j", appChain,
		})
	}

	return append(rules, i.legacyProxyRules(tcpPorts, proxyPort, proxyPortSetName, mark)...)
}

func (i *Instance) legacyProxyRules(tcpPorts string, proxyPort string, proxyPortSetName string, cgroupMark string) [][]string {
	destSetName, srvSetName := i.getSetNames(proxyPortSetName)

	aclInfo := ACLInfo{
		MangleTable:         i.appPacketIPTableContext,
		NatTable:            i.appProxyIPTableContext,
		MangleProxyAppChain: proxyOutputChain,
		MangleProxyNetChain: proxyInputChain,
		NatProxyNetChain:    natProxyInputChain,
		NatProxyAppChain:    natProxyOutputChain,
		CgroupMark:          cgroupMark,
		DestIPSet:           destSetName,
		SrvIPSet:            srvSetName,
		ProxyPort:           proxyPort,
		ProxyMark:           proxyMark,
		TCPPorts:            tcpPorts,
	}

	tmpl := template.Must(template.New(legacyProxyRules).Funcs(template.FuncMap{
		"isCgroupSet": func() bool {
			return cgroupMark != ""
		},
	}).Parse(legacyProxyRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}
	return rules
}
