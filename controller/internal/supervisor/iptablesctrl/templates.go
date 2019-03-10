package iptablesctrl

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/template"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/monitor/extractors"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
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
	PUType    string
	// Chains
	MangleTable         string
	NatTable            string
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
	DefaultConnmark       string
	QueueBalanceAppSyn    string
	QueueBalanceAppSynAck string
	QueueBalanceAppAck    string
	QueueBalanceNetSyn    string
	QueueBalanceNetSynAck string
	QueueBalanceNetAck    string
	InitialMarkVal        string
	RawSocketMark         string
	TargetNetSet          string

	// UDP rules
	Numpackets   string
	InitialCount string
	UDPSignature string

	// Linux PUs
	TCPPorts   string
	UDPPorts   string
	TCPPortSet string

	// ProxyRules
	DestIPSet    string
	SrvIPSet     string
	ProxyPort    string
	CgroupMark   string
	ProxyMark    string
	ProxySetName string

	// UID PUs
	Mark    string
	UID     string
	PortSet string

	NFLOGPrefix string

	// ExcludedACLS
	Exclusions []string
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

//getSetNames returns a pair of strings represent proxySetNames
func getSetNames(portSetName string) (string, string) {
	return "dst-" + portSetName, "srv-" + portSetName
}

func (i *Instance) newACLInfo(version int, contextID string, p *policy.PUInfo, puType string) (*ACLInfo, error) {

	var appChain, netChain string
	var err error

	if contextID != "" {
		appChain, netChain, err = chainName(contextID, version)
		if err != nil {
			return nil, err
		}
	}

	var tcpPorts, udpPorts string
	var servicePort, mark, uid string
	var excludedNetworks []string
	if p != nil {
		tcpPorts, udpPorts = common.ConvertServicesToProtocolPortList(p.Runtime.Options().Services)
		puType = extractors.GetPuType(p.Runtime)
		servicePort = p.Policy.ServicesListeningPort()
		mark = p.Runtime.Options().CgroupMark
		uid = p.Runtime.Options().UserID
		excludedNetworks = p.Policy.ExcludedNetworks()
	}

	proxySetName := puPortSetName(contextID, proxyPortSetPrefix)
	destSetName, srvSetName := getSetNames(proxySetName)

	appSection := ""
	netSection := ""
	switch puType {
	case extractors.LinuxPU:
		appSection = TriremeOutput
		netSection = TriremeInput
	case extractors.HostModeNetworkPU:
		appSection = NetworkSvcOutput
		netSection = NetworkSvcInput
	case extractors.HostPU:
		appSection = HostModeOutput
		netSection = HostModeInput
	default:
		appSection = ipTableSectionOutput
		netSection = ipTableSectionInput
	}

	portSetName := i.getPortSet(contextID)

	cfg := &ACLInfo{
		ContextID: contextID,
		PUType:    puType,
		// Chains
		MangleTable:         "mangle",
		NatTable:            "nat",
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
		DefaultConnmark:       strconv.Itoa(int(constants.DefaultConnMark)),
		QueueBalanceAppSyn:    i.fqc.GetApplicationQueueSynStr(),
		QueueBalanceAppSynAck: i.fqc.GetApplicationQueueSynAckStr(),
		QueueBalanceAppAck:    i.fqc.GetApplicationQueueAckStr(),
		QueueBalanceNetSyn:    i.fqc.GetNetworkQueueSynStr(),
		QueueBalanceNetSynAck: i.fqc.GetNetworkQueueSynAckStr(),
		QueueBalanceNetAck:    i.fqc.GetNetworkQueueAckStr(),
		InitialMarkVal:        strconv.Itoa(cgnetcls.Initialmarkval - 1),
		RawSocketMark:         strconv.Itoa(afinetrawsocket.ApplicationRawSocketMark),
		TargetNetSet:          targetNetworkSet,

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
		CgroupMark:   mark,
		ProxyMark:    proxyMark,
		ProxySetName: proxySetName,

		// // UID PUs
		UID:     uid,
		Mark:    mark,
		PortSet: proxySetName,

		NFLOGPrefix: policy.DefaultAcceptLogPrefix(contextID),

		// ExcludedACLS
		Exclusions: excludedNetworks,
	}

	return cfg, nil
}
