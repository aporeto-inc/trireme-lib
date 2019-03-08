package iptablesctrl

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
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

	// Chains
	MangleTable               string
	NatTable                  string
	HostInput                 string
	HostOutput                string
	NetworkSvcInput           string
	NetworkSvcOutput          string
	TriremeInput              string
	TriremeOutput             string
	EncryptNetworkService     string
	EncryptApplicationService string
	ProxyInput                string
	ProxyOutput               string
	UIDInput                  string
	UIDOutput                 string
	NatProxyNetChain          string
	NatProxyAppChain          string
	MangleProxyNetChain       string
	MangleProxyAppChain       string
	PreRouting                string

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
	DestIPSet  string
	SrvIPSet   string
	ProxyPort  string
	CgroupMark string
	ProxyMark  string

	// UID PUs
	Mark    string
	UID     string
	PortSet string

	NFLOGPrefix string

	// ExcludedACLS
	Exclusions []string
}
