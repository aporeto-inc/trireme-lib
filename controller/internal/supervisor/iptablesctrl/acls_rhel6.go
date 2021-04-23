// +build rhel6

package iptablesctrl

import (
	"strings"
	"text/template"

	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/gaia/protocols"
	"go.uber.org/zap"
)

const (
	tcpProto  = "tcp"
	icmpProto = "icmp"
	udpProto  = "udp"
)

func (i *iptables) aclSkipProto(proto string) bool {
	if splits := strings.Split(proto, "/"); strings.ToUpper(splits[0]) == protocols.L4ProtocolICMP || strings.ToUpper(splits[0]) == protocols.L4ProtocolICMP6 {
		return true
	}
	return false
}

// This refers to the pu chain rules for pus in older distros like RH 6.9/Ubuntu 14.04. The rules
// consider source ports to identify packets from the process.
func (i *iptables) legacyPuChainRules(cfg *ACLInfo) ([][]string, bool) {
	if !(cfg.PUType == common.HostNetworkPU || cfg.PUType == common.HostPU) {
		return nil, false
	}

	iptableCgroupSection := cfg.AppSection
	iptableNetSection := cfg.NetSection
	rules := [][]string{}
	if cfg.TCPPorts != "0" {
		rules = append(rules, [][]string{
			{
				appPacketIPTableContext,
				iptableCgroupSection,
				"-p", icmpProto,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", "MARK", "--set-mark", cfg.PacketMark,
			},
			{
				appPacketIPTableContext,
				iptableCgroupSection,
				"-p", tcpProto,
				"-m", "multiport",
				"--source-ports", cfg.TCPPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", "MARK", "--set-mark", cfg.PacketMark,
			},
			{
				appPacketIPTableContext,
				iptableCgroupSection,
				"-p", tcpProto,
				"-m", "multiport",
				"--source-ports", cfg.TCPPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", cfg.AppChain,
			},
			{
				netPacketIPTableContext,
				iptableNetSection,
				"-p", tcpProto,
				"-m", "multiport",
				"--destination-ports", cfg.TCPPorts,
				"-m", "comment", "--comment", "Container-specific-chain",
				"-j", cfg.NetChain,
			}}...)
	}

	if cfg.UDPPorts != "0" {
		rules = append(rules, [][]string{
			{
				appPacketIPTableContext,
				iptableCgroupSection,
				"-p", udpProto,
				"-m", "multiport",
				"--source-ports", cfg.UDPPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", "MARK", "--set-mark", cfg.PacketMark,
			},
			{
				appPacketIPTableContext,
				iptableCgroupSection,
				"-p", udpProto, "-m", "mark", "--mark", cfg.PacketMark,
				"-m", "addrtype", "--src-type", "LOCAL",
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-m", "state", "--state", "NEW",
				"-j", "NFLOG", "--nflog-group", "10",
				"--nflog-prefix", policy.DefaultLogPrefix(cfg.ContextID, policy.Accept),
			},
			{
				appPacketIPTableContext,
				iptableCgroupSection,
				"-m", "comment", "--comment", "traffic-same-pu",
				"-p", udpProto, "-m", "mark", "--mark", cfg.PacketMark,
				"-m", "addrtype", "--src-type", "LOCAL",
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-j", "ACCEPT",
			},
			{
				appPacketIPTableContext,
				iptableCgroupSection,
				"-p", udpProto,
				"-m", "multiport",
				"--source-ports", cfg.UDPPorts,
				"-m", "comment", "--comment", "Server-specific-chain",
				"-j", cfg.AppChain,
			},
			{
				netPacketIPTableContext,
				iptableNetSection,
				"-m", "comment", "--comment", "traffic-same-pu",
				"-p", udpProto, "-m", "mark", "--mark", cfg.PacketMark,
				"-m", "addrtype", "--src-type", "LOCAL",
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-j", "ACCEPT",
			},
			{
				netPacketIPTableContext,
				iptableNetSection,
				"-p", udpProto,
				"-m", "multiport",
				"--destination-ports", cfg.UDPPorts,
				"-m", "comment", "--comment", "Container-specific-chain",
				"-j", cfg.NetChain,
			}}...)
	}

	if cfg.PUType == common.HostPU {
		// Add a capture all traffic rule for host pu. This traps all traffic going out
		// of the box.

		rules = append(rules, []string{
			appPacketIPTableContext,
			iptableCgroupSection,
			"-m", "comment", "--comment", "capture all outgoing traffic",
			"-j", cfg.AppChain,
		})
		rules = append(rules, []string{
			netPacketIPTableContext,
			iptableNetSection,
			"-m", "comment", "--comment", "capture all outgoing traffic",
			"-j", cfg.NetChain,
		})
	}

	return append(rules, i.legacyProxyRules(cfg.TCPPorts, cfg.ProxyPort, cfg.DestIPSet, cfg.SrvIPSet, cfg.PacketMark, cfg.DNSProxyPort, cfg.DNSServerIP)...), true
}

func (i *iptables) legacyProxyRules(tcpPorts, proxyPort, destSetName, srvSetName, cgroupMark, dnsProxyPort, dnsServerIP string) [][]string {

	aclInfo := ACLInfo{
		MangleTable:         appPacketIPTableContext,
		NatTable:            appProxyIPTableContext,
		MangleProxyAppChain: proxyOutputChain,
		MangleProxyNetChain: proxyInputChain,
		NatProxyNetChain:    natProxyInputChain,
		NatProxyAppChain:    natProxyOutputChain,
		CgroupMark:          cgroupMark,
		DestIPSet:           destSetName,
		SrvIPSet:            srvSetName,
		ProxyPort:           proxyPort,
		ProxyMark:           constants.ProxyMark,
		TCPPorts:            tcpPorts,
		DNSProxyPort:        dnsProxyPort,
		DNSServerIP:         dnsServerIP,
	}

	tmpl := template.Must(template.New(legacyProxyRules).Funcs(template.FuncMap{
		"isCgroupSet": func() bool {
			return cgroupMark != ""
		},
		"enableDNSProxy": func() bool {
			return dnsServerIP != ""
		},
	}).Parse(legacyProxyRules))

	rules, err := extractRulesFromTemplate(tmpl, aclInfo)
	if err != nil {
		zap.L().Warn("unable to extract rules", zap.Error(err))
	}
	return rules
}
