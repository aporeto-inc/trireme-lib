package iptablesctrl

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"text/template"

	"github.com/kballard/go-shellquote"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	cconstants "go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/constants"
)

func extractRulesFromTemplate(tmpl *template.Template, data interface{}) ([][]string, error) {

	buffer := bytes.NewBuffer([]byte{})
	if err := tmpl.Execute(buffer, data); err != nil {
		return [][]string{}, fmt.Errorf("unable to execute template:%s", err)
	}

	rules := [][]string{}

	for _, m := range strings.Split(buffer.String(), "\n") {

		rule, err := shellquote.Split(m)
		if err != nil {
			return [][]string{}, err
		}

		// ignore empty lines in the buffer
		if len(rule) <= 1 {
			continue
		}

		rules = append(rules, rule)
	}
	return rules, nil
}

// ACLInfo keeps track of all information to create ACLs
type ACLInfo struct {
	ContextID string
	PUType    common.PUType

	// Tables
	MangleTable string
	NatTable    string

	// Chains
	MainAppChain        string
	MainNetChain        string
	BPFPath             string
	HostInput           string
	HostOutput          string
	NfqueueOutput       string
	NfqueueInput        string
	NetworkSvcInput     string
	NetworkSvcOutput    string
	TriremeInput        string
	TriremeOutput       string
	NatProxyNetChain    string
	NatProxyAppChain    string
	MangleProxyNetChain string
	MangleProxyAppChain string
	PreRouting          string

	AppChain   string
	NetChain   string
	AppSection string
	NetSection string

	// serviceMesh chains
	IstioChain string

	// common info
	DefaultConnmark         string
	DefaultDropConnmark     string
	DefaultExternalConnmark string
	PacketMarkToSetConnmark string
	DefaultInputMark        string
	DefaultHandShakeMark    string

	RawSocketMark   string
	TargetTCPNetSet string
	TargetUDPNetSet string
	ExclusionsSet   string
	IpsetPrefix     string
	// IPv4 IPv6
	DefaultIP     string
	needICMPRules bool

	// UDP rules
	Numpackets   string
	InitialCount string
	UDPSignature string

	// Linux PUs
	TCPPorts   string
	UDPPorts   string
	TCPPortSet string

	// ProxyRules
	DestIPSet     string
	SrvIPSet      string
	ProxyPort     string
	DNSProxyPort  string
	DNSServerIP   string
	CgroupMark    string
	ProxyMark     string
	AuthPhaseMark string

	PacketMark string
	Mark       string
	PortSet    string

	AppNFLOGPrefix              string
	AppNFLOGDropPacketLogPrefix string
	AppDefaultAction            string

	NetNFLOGPrefix              string
	NetNFLOGDropPacketLogPrefix string
	NetDefaultAction            string

	NFQueues    []int
	NumNFQueues int
	// icmpv6 allow bytecode
	ICMPv6Allow string

	// Istio Iptable rules
	IstioEnabled bool
}

func chainName(contextID string, version int) (app, net string, err error) {
	hash := md5.New()

	if _, err := io.WriteString(hash, contextID); err != nil {
		return "", "", err
	}
	output := base64.URLEncoding.EncodeToString(hash.Sum(nil))
	if len(contextID) > 4 {
		contextID = contextID[:4] + output[:6]
	} else {
		contextID = contextID + output[:6]
	}

	app = appChainPrefix + contextID + "-" + strconv.Itoa(version)
	net = netChainPrefix + contextID + "-" + strconv.Itoa(version)

	return app, net, nil
}

func (i *iptables) newACLInfo(version int, contextID string, p *policy.PUInfo, puType common.PUType) (*ACLInfo, error) {
	var appChain, netChain string
	var err error
	var nfqueues []int

	numQueues := i.fqc.GetNumQueues()

	ipFilter := i.impl.IPFilter()

	if contextID != "" {
		appChain, netChain, err = chainName(contextID, version)
		if err != nil {
			return nil, err
		}
	}

	parseDNSServerIP := func() string {
		for _, ipString := range i.fqc.GetDNSServerAddresses() {
			if ip := net.ParseIP(ipString); ip != nil {
				if ipFilter(ip) {
					return ipString
				}

				continue
			}
			// parseCIDR
			if ip, _, err := net.ParseCIDR(ipString); err == nil {
				if ipFilter(ip) {
					return ipString
				}
			}
		}
		return ""
	}

	appDefaultAction := policy.Reject | policy.Log
	netDefaultAction := policy.Reject | policy.Log

	var tcpPorts, udpPorts string
	var servicePort, mark, dnsProxyPort, packetMark string
	if p != nil {
		tcpPorts, udpPorts = common.ConvertServicesToProtocolPortList(p.Runtime.Options().Services)
		puType = p.Runtime.PUType()
		servicePort = p.Policy.ServicesListeningPort()
		dnsProxyPort = p.Policy.DNSProxyPort()
		mark = p.Runtime.Options().CgroupMark
		packetMark = mark
		appDefaultAction = p.Policy.AppDefaultPolicyAction()
		netDefaultAction = p.Policy.NetDefaultPolicyAction()
	}

	destSetName, srvSetName := i.ipsetmanager.GetProxySetNames(contextID)

	tcpTargetSetName, udpTargetSetName, excludedNetworkSetName := i.ipsetmanager.GetIPsetNamesForTargetAndExcludedNetworks()

	appSection := ""
	netSection := ""
	switch puType {
	case common.LinuxProcessPU, common.WindowsProcessPU:
		appSection = TriremeOutput
		netSection = TriremeInput
	case common.HostNetworkPU:
		appSection = NetworkSvcOutput
		netSection = NetworkSvcInput
	case common.HostPU:
		appSection = HostModeOutput
		netSection = HostModeInput
	default:
		appSection = mainAppChain
		netSection = mainNetChain
	}

	portSetName := i.ipsetmanager.GetServerPortSetName(contextID)

	for i := 0; i < numQueues; i++ {
		nfqueues = append(nfqueues, i)
	}

	cfg := &ACLInfo{
		ContextID: contextID,
		PUType:    puType,
		// Chains
		MangleTable:         "mangle",
		NatTable:            "nat",
		MainAppChain:        mainAppChain,
		MainNetChain:        mainNetChain,
		HostInput:           HostModeInput,
		HostOutput:          HostModeOutput,
		NfqueueOutput:       NfqueueOutput,
		NfqueueInput:        NfqueueInput,
		NFQueues:            nfqueues,
		NumNFQueues:         numQueues,
		NetworkSvcInput:     NetworkSvcInput,
		NetworkSvcOutput:    NetworkSvcOutput,
		TriremeInput:        TriremeInput,
		TriremeOutput:       TriremeOutput,
		NatProxyNetChain:    natProxyInputChain,
		NatProxyAppChain:    natProxyOutputChain,
		MangleProxyNetChain: proxyInputChain,
		MangleProxyAppChain: proxyOutputChain,
		PreRouting:          ipTableSectionPreRouting,

		AppChain:   appChain,
		NetChain:   netChain,
		AppSection: appSection,
		NetSection: netSection,
		IstioChain: istioChain,

		// common info
		DefaultConnmark:         strconv.Itoa(int(constants.DefaultConnMark)),
		DefaultDropConnmark:     strconv.Itoa(int(constants.DropConnmark)),
		DefaultExternalConnmark: strconv.Itoa(int(constants.DefaultExternalConnMark)),
		PacketMarkToSetConnmark: strconv.Itoa(int(constants.PacketMarkToSetConnmark)),
		DefaultInputMark:        strconv.Itoa(int(constants.DefaultInputMark)),
		RawSocketMark:           strconv.Itoa(afinetrawsocket.ApplicationRawSocketMark),
		DefaultHandShakeMark:    strconv.Itoa(int(constants.HandshakeConnmark)),
		CgroupMark:              mark,
		TargetTCPNetSet:         tcpTargetSetName,
		TargetUDPNetSet:         udpTargetSetName,
		ExclusionsSet:           excludedNetworkSetName,
		// IPv4 vs IPv6
		DefaultIP:     i.impl.GetDefaultIP(),
		needICMPRules: i.impl.NeedICMP(),

		// UDP rules
		Numpackets:   numPackets,
		InitialCount: initialCount,
		UDPSignature: packet.UDPAuthMarker,

		// // Linux PUs
		TCPPorts:   tcpPorts,
		UDPPorts:   udpPorts,
		TCPPortSet: portSetName,

		// // ProxyRules
		DestIPSet:    destSetName,
		SrvIPSet:     srvSetName,
		ProxyPort:    servicePort,
		DNSProxyPort: dnsProxyPort,
		DNSServerIP:  parseDNSServerIP(),
		ProxyMark:    cconstants.ProxyMark,

		// PUs
		PacketMark: packetMark,
		Mark:       mark,
		PortSet:    portSetName,

		AppNFLOGPrefix:              policy.DefaultLogPrefix(contextID, appDefaultAction),
		AppNFLOGDropPacketLogPrefix: policy.DefaultDropPacketLogPrefix(contextID),
		AppDefaultAction:            policy.DefaultAction(appDefaultAction),

		NetNFLOGPrefix:              policy.DefaultLogPrefix(contextID, netDefaultAction),
		NetNFLOGDropPacketLogPrefix: policy.DefaultDropPacketLogPrefix(contextID),
		NetDefaultAction:            policy.DefaultAction(netDefaultAction),
	}

	allowICMPv6(cfg)
	if i.bpf != nil {
		cfg.BPFPath = i.bpf.GetBPFPath()
	}

	return cfg, nil
}
