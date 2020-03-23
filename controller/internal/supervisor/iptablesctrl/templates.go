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

	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.aporeto.io/trireme-lib/v11/utils/constants"
)

func extractRulesFromTemplate(tmpl *template.Template, data interface{}) ([][]string, error) {

	buffer := bytes.NewBuffer([]byte{})
	if err := tmpl.Execute(buffer, data); err != nil {
		return [][]string{}, fmt.Errorf("unable to execute template:%s", err)
	}

	rules := [][]string{}
	for _, m := range strings.Split(buffer.String(), "\n") {
		rule := strings.Fields(m)
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
	NetworkSvcInput     string
	NetworkSvcOutput    string
	TriremeInput        string
	TriremeOutput       string
	UIDInput            string
	UIDOutput           string
	NatProxyNetChain    string
	NatProxyAppChain    string
	MangleProxyNetChain string
	MangleProxyAppChain string
	PreRouting          string

	AppChain   string
	NetChain   string
	AppSection string
	NetSection string

	// common info
	DefaultConnmark         string
	DefaultExternalConnmark string
	QueueBalanceAppSyn      string
	QueueBalanceAppSynAck   string
	QueueBalanceAppAck      string
	QueueBalanceNetSyn      string
	QueueBalanceNetSynAck   string
	QueueBalanceNetAck      string

	InitialMarkVal  string
	RawSocketMark   string
	TargetTCPNetSet string
	TargetUDPNetSet string
	ExclusionsSet   string
	IpsetPrefix     string
	NetSynQueues    []uint32
	NetAckQueues    []uint32
	NetSynAckQueues []uint32
	AppSynQueues    []uint32
	AppSynAckQueues []uint32
	AppAckQueues    []uint32
	QueueMask       string
	MarkMask        string
	HMarkRandomSeed string
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
	ProxySetName  string

	// UID PUs
	PacketMark             string
	Mark                   string
	UID                    string
	PortSet                string
	NFLOGPrefix            string
	NFLOGAcceptPrefix      string
	DefaultNFLOGDropPrefix string
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

	ipsetPrefix := i.impl.GetIPSetPrefix()
	ipFilter := i.impl.IPFilter()

	if contextID != "" {
		appChain, netChain, err = chainName(contextID, version)
		if err != nil {
			return nil, err
		}
	}

	parseDNSServerIP := func() string {
		for _, ipString := range i.fqc.DNSServerAddress {
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

	var tcpPorts, udpPorts string
	var servicePort, mark, uid, dnsProxyPort, packetMark string
	queueMask := "0x" + strconv.FormatUint(uint64(constants.NFQueueMask), 16)
	markMask := "0x" + strconv.FormatUint(uint64(constants.NFSetMarkMask), 16)

	hmarkRandomSeed := "0x" + strconv.FormatUint(uint64(constants.HMARKRandomSeed), 16)
	if p != nil {
		tcpPorts, udpPorts = common.ConvertServicesToProtocolPortList(p.Runtime.Options().Services)
		puType = p.Runtime.PUType()
		servicePort = p.Policy.ServicesListeningPort()
		dnsProxyPort = p.Policy.DNSProxyPort()
		mark = p.Runtime.Options().CgroupMark
		markIntVal, _ := strconv.Atoi(mark)
		packetMark = strconv.Itoa(markIntVal << constants.MarkShift)
		uid = p.Runtime.Options().UserID
	}

	proxyPrefix := ipsetPrefix + proxyPortSetPrefix
	proxySetName := puPortSetName(contextID, proxyPrefix)
	destSetName, srvSetName := i.getSetNames(proxySetName)

	appSection := ""
	netSection := ""
	switch puType {
	case common.LinuxProcessPU, common.SSHSessionPU:
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

	portSetName := i.getPortSet(contextID)

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
		NetworkSvcInput:     NetworkSvcInput,
		NetworkSvcOutput:    NetworkSvcOutput,
		TriremeInput:        TriremeInput,
		TriremeOutput:       TriremeOutput,
		UIDInput:            uidInput,
		UIDOutput:           uidchain,
		NatProxyNetChain:    natProxyInputChain,
		NatProxyAppChain:    natProxyOutputChain,
		MangleProxyNetChain: proxyInputChain,
		MangleProxyAppChain: proxyOutputChain,
		PreRouting:          ipTableSectionPreRouting,

		AppChain:   appChain,
		NetChain:   netChain,
		AppSection: appSection,
		NetSection: netSection,

		// common info
		DefaultConnmark:         strconv.Itoa(int(constants.DefaultConnMark)),
		DefaultExternalConnmark: strconv.Itoa(int(constants.DefaultExternalConnMark)),
		QueueBalanceAppSyn:      i.fqc.GetApplicationQueueSynStr(),
		QueueBalanceAppSynAck:   i.fqc.GetApplicationQueueSynAckStr(),
		QueueBalanceAppAck:      i.fqc.GetApplicationQueueAckStr(),
		QueueBalanceNetSyn:      i.fqc.GetNetworkQueueSynStr(),
		QueueBalanceNetSynAck:   i.fqc.GetNetworkQueueSynAckStr(),
		QueueBalanceNetAck:      i.fqc.GetNetworkQueueAckStr(),
		NetSynQueues:            i.fqc.NetworkSynQueues,
		NetAckQueues:            i.fqc.NetworkAckQueues,
		NetSynAckQueues:         i.fqc.NetworkSynAckQueues,
		AppSynQueues:            i.fqc.ApplicationSynQueues,
		AppSynAckQueues:         i.fqc.ApplicationSynAckQueues,
		AppAckQueues:            i.fqc.ApplicationAckQueues,
		InitialMarkVal:          strconv.Itoa((constants.Initialmarkval - 1) << constants.MarkShift),
		RawSocketMark:           strconv.Itoa(afinetrawsocket.ApplicationRawSocketMark),
		CgroupMark:              mark,
		TargetTCPNetSet:         ipsetPrefix + targetTCPNetworkSet,
		TargetUDPNetSet:         ipsetPrefix + targetUDPNetworkSet,
		ExclusionsSet:           ipsetPrefix + excludedNetworkSet,
		IpsetPrefix:             ipsetPrefix,
		QueueMask:               queueMask,
		MarkMask:                markMask,
		HMarkRandomSeed:         hmarkRandomSeed,
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
		ProxyMark:    proxyMark,
		ProxySetName: proxySetName,

		// // UID PUs
		UID:        uid,
		PacketMark: packetMark,
		Mark:       mark,
		PortSet:    portSetName,

		NFLOGPrefix:            policy.DefaultLogPrefix(contextID),
		NFLOGAcceptPrefix:      policy.DefaultAcceptLogPrefix(contextID),
		DefaultNFLOGDropPrefix: policy.DefaultDroppedPacketLogPrefix(contextID),
	}

	if i.bpf != nil {
		cfg.BPFPath = i.bpf.GetBPFPath()
	}

	return cfg, nil
}
