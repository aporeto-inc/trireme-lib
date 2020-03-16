// +build windows

package windows

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/DavidGamba/go-getoptions"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
)

// WindowsRuleMatchSet represents result of parsed --match-set
type WindowsRuleMatchSet struct { //nolint:golint // ignore type name stutters
	MatchSetName    string
	MatchSetNegate  bool
	MatchSetDstIP   bool
	MatchSetDstPort bool
	MatchSetSrcIP   bool
	MatchSetSrcPort bool
}

// WindowsRulePortRange represents parsed port range
type WindowsRulePortRange struct { //nolint:golint // ignore type name stutters
	PortStart int
	PortEnd   int
}

// WindowsRuleSpec represents result of parsed iptables rule
type WindowsRuleSpec struct { //nolint:golint // ignore type name stutters
	Protocol         int
	Action           int // FilterAction (allow, drop, nfq, proxy)
	ProxyPort        int
	Mark             int
	Log              bool
	LogPrefix        string
	GroupID          int
	MatchSrcPort     []*WindowsRulePortRange
	MatchDstPort     []*WindowsRulePortRange
	MatchBytes       []byte
	MatchBytesOffset int
	MatchSet         []*WindowsRuleMatchSet
}

// MakeRuleSpecText converts a WindowsRuleSpec back into a string for an iptables rule
func MakeRuleSpecText(winRuleSpec *WindowsRuleSpec, validate bool) (string, error) {
	rulespec := ""
	if winRuleSpec.Protocol > 0 && winRuleSpec.Protocol < math.MaxUint8 {
		rulespec += fmt.Sprintf("-p %d ", winRuleSpec.Protocol)
	}
	if len(winRuleSpec.MatchBytes) > 0 {
		rulespec += fmt.Sprintf("-m string --string %s --offset %d ", string(winRuleSpec.MatchBytes), winRuleSpec.MatchBytesOffset)
	}
	if len(winRuleSpec.MatchSrcPort) > 0 {
		rulespec += "--sports "
		for i, pr := range winRuleSpec.MatchSrcPort {
			rulespec += strconv.Itoa(pr.PortStart)
			if pr.PortStart != pr.PortEnd {
				rulespec += fmt.Sprintf(":%d", pr.PortEnd)
			}
			if i+1 < len(winRuleSpec.MatchSrcPort) {
				rulespec += ","
			}
		}
		rulespec += " "
	}
	if len(winRuleSpec.MatchDstPort) > 0 {
		rulespec += "--dports "
		for i, pr := range winRuleSpec.MatchDstPort {
			rulespec += strconv.Itoa(pr.PortStart)
			if pr.PortStart != pr.PortEnd {
				rulespec += fmt.Sprintf(":%d", pr.PortEnd)
			}
			if i+1 < len(winRuleSpec.MatchDstPort) {
				rulespec += ","
			}
		}
		rulespec += " "
	}
	if len(winRuleSpec.MatchSet) > 0 {
		for _, ms := range winRuleSpec.MatchSet {
			rulespec += "-m set "
			if ms.MatchSetNegate {
				rulespec += "! "
			}
			rulespec += fmt.Sprintf("--match-set %s ", ms.MatchSetName)
			if ms.MatchSetSrcIP {
				rulespec += "srcIP"
				if ms.MatchSetSrcPort || ms.MatchSetDstPort {
					rulespec += ","
				}
			} else if ms.MatchSetDstIP {
				rulespec += "dstIP"
				if ms.MatchSetSrcPort || ms.MatchSetDstPort {
					rulespec += ","
				}
			}
			if ms.MatchSetSrcPort {
				rulespec += "srcPort"
			} else if ms.MatchSetDstPort {
				rulespec += "dstPort"
			}
			rulespec += " "
		}
	}
	switch winRuleSpec.Action {
	case frontman.FilterActionAllow:
		rulespec += "-j ACCEPT "
	case frontman.FilterActionBlock:
		rulespec += "-j DROP "
	case frontman.FilterActionProxy:
		rulespec += fmt.Sprintf("-j REDIRECT --to-ports %d ", winRuleSpec.ProxyPort)
	case frontman.FilterActionNfq:
		rulespec += fmt.Sprintf("-j NFQUEUE -j MARK %d ", winRuleSpec.Mark)
	case frontman.FilterActionForceNfq:
		rulespec += fmt.Sprintf("-j NFQUEUE --queue-force -j MARK %d ", winRuleSpec.Mark)
	}
	if winRuleSpec.Log {
		rulespec += fmt.Sprintf("-j NFLOG --nflog-group %d --nflog-prefix %s ", winRuleSpec.GroupID, winRuleSpec.LogPrefix)
	}
	rulespec = strings.TrimSpace(rulespec)
	if validate {
		if _, err := ParseRuleSpec(strings.Split(rulespec, " ")...); err != nil {
			return "", err
		}
	}
	return rulespec, nil
}

// ParsePortString parses comma-separated list of port or port ranges
func ParsePortString(portString string) ([]*WindowsRulePortRange, error) {
	var result []*WindowsRulePortRange
	if portString != "" {
		portList := strings.Split(portString, ",")
		for _, portListItem := range portList {
			portEnd := 0
			portStart, err := strconv.Atoi(portListItem)
			if err != nil {
				portRange := strings.SplitN(portListItem, ":", 2)
				if len(portRange) != 2 {
					return nil, errors.New("invalid port string")
				}
				portStart, err = strconv.Atoi(portRange[0])
				if err != nil {
					return nil, errors.New("invalid port string")
				}
				portEnd, err = strconv.Atoi(portRange[1])
				if err != nil {
					return nil, errors.New("invalid port string")
				}
			}
			if portEnd == 0 {
				portEnd = portStart
			}
			result = append(result, &WindowsRulePortRange{portStart, portEnd})
		}
	}
	return result, nil
}

// ParseRuleSpec parses a windows iptable rule
func ParseRuleSpec(rulespec ...string) (*WindowsRuleSpec, error) {

	opt := getoptions.New()

	protocolOpt := opt.String("p", "")
	sPortOpt := opt.String("sports", "")
	dPortOpt := opt.String("dports", "")
	actionOpt := opt.StringSlice("j", 1, 10, opt.Required())
	modeOpt := opt.StringSlice("m", 1, 10)
	matchSetOpt := opt.StringSlice("match-set", 2, 10)
	matchStringOpt := opt.String("string", "")
	matchStringOffsetOpt := opt.Int("offset", 0)
	redirectPortOpt := opt.Int("to-ports", 0)
	opt.String("state", "") // "--state NEW" et al ignored
	opt.String("match", "") // "--match multiport" ignored
	groupIDOpt := opt.Int("nflog-group", 0)
	logPrefixOpt := opt.String("nflog-prefix", "")
	nfqForceOpt := opt.Bool("queue-force", false)

	_, err := opt.Parse(rulespec)
	if err != nil {
		return nil, err
	}

	result := &WindowsRuleSpec{}

	// protocol
	isProtoAnyRule := false
	switch strings.ToLower(*protocolOpt) {
	case "tcp":
		result.Protocol = packet.IPProtocolTCP
	case "udp":
		result.Protocol = packet.IPProtocolUDP
	case "icmp":
		result.Protocol = 1
	case "": // not specified = all
		fallthrough
	case "all":
		result.Protocol = -1
		isProtoAnyRule = true
	default:
		result.Protocol, err = strconv.Atoi(*protocolOpt)
		if err != nil {
			return nil, errors.New("rulespec not valid: invalid protocol")
		}
		if result.Protocol < 0 || result.Protocol > math.MaxUint8 {
			return nil, errors.New("rulespec not valid: invalid protocol")
		}
		// iptables man page says protocol zero is equivalent to 'all' (sorry, IPv6 Hop-by-Hop Option)
		if result.Protocol == 0 {
			result.Protocol = -1
		}
	}

	// src/dest port: either port or port range or list of such
	result.MatchSrcPort, err = ParsePortString(*sPortOpt)
	if err != nil {
		return nil, errors.New("rulespec not valid: invalid match port")
	}
	result.MatchDstPort, err = ParsePortString(*dPortOpt)
	if err != nil {
		return nil, errors.New("rulespec not valid: invalid match port")
	}

	// -m options
	for i, modeOptSetNum := 0, 0; i < len(*modeOpt); i++ {
		switch (*modeOpt)[i] {
		case "set":
			matchSet := &WindowsRuleMatchSet{}
			// see if negate of --match-set occurred
			if i+1 < len(*modeOpt) && (*modeOpt)[i+1] == "!" {
				matchSet.MatchSetNegate = true
				i++
			}
			// now check corresponding match-set by index
			matchSetIndex := 2 * modeOptSetNum
			modeOptSetNum++
			if matchSetIndex+1 >= len(*matchSetOpt) {
				return nil, errors.New("rulespec not valid: --match-set not found for -m set")
			}
			// first part is the ipset name
			matchSet.MatchSetName = (*matchSetOpt)[matchSetIndex]
			// second part is the dst/src match specifier
			ipPortSpecLower := strings.ToLower((*matchSetOpt)[matchSetIndex+1])
			if strings.HasPrefix(ipPortSpecLower, "dstip") {
				matchSet.MatchSetDstIP = true
			} else if strings.HasPrefix(ipPortSpecLower, "srcip") {
				matchSet.MatchSetSrcIP = true
			}
			if strings.HasSuffix(ipPortSpecLower, "dstport") {
				matchSet.MatchSetDstPort = true
				if result.Protocol < 1 {
					return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
				}
			} else if strings.HasSuffix(ipPortSpecLower, "srcport") {
				matchSet.MatchSetSrcPort = true
				if result.Protocol < 1 {
					return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
				}
			}
			if !matchSet.MatchSetDstIP && !matchSet.MatchSetDstPort && !matchSet.MatchSetSrcIP && !matchSet.MatchSetSrcPort {
				// look for acl-created iptables-conforming match on 'dst' or 'src'.
				// a dst or src by itself we take to mean match both. otherwise, we take it as ip-match,port-match.
				if strings.HasPrefix(ipPortSpecLower, "dst") {
					matchSet.MatchSetDstIP = true
				} else if strings.HasPrefix(ipPortSpecLower, "src") {
					matchSet.MatchSetSrcIP = true
				}
				if strings.HasSuffix(ipPortSpecLower, "dst") && !isProtoAnyRule {
					matchSet.MatchSetDstPort = true
					if result.Protocol < 1 {
						return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
					}
				} else if strings.HasSuffix(ipPortSpecLower, "src") && !isProtoAnyRule {
					matchSet.MatchSetSrcPort = true
					if result.Protocol < 1 {
						return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
					}
				}
			}
			if !matchSet.MatchSetDstIP && !matchSet.MatchSetDstPort && !matchSet.MatchSetSrcIP && !matchSet.MatchSetSrcPort {
				return nil, errors.New("rulespec not valid: ipset match needs ip/port specifier")
			}
			result.MatchSet = append(result.MatchSet, matchSet)

		case "string":
			if *matchStringOpt == "" {
				return nil, errors.New("rulespec not valid: no match string given")
			}
			result.MatchBytes = []byte(*matchStringOpt)
			result.MatchBytesOffset = *matchStringOffsetOpt

		case "state":
			// for "-m state --state NEW"
			// skip it for now

		default:
			return nil, errors.New("rulespec not valid: unknown -m option")
		}
	}

	// action: either NFQUEUE, REDIRECT, MARK, ACCEPT, DROP, NFLOG
	for i := 0; i < len(*actionOpt); i++ {
		switch (*actionOpt)[i] {
		case "NFQUEUE":
			result.Action = frontman.FilterActionNfq
			if *nfqForceOpt {
				result.Action = frontman.FilterActionForceNfq
			}
		case "REDIRECT":
			result.Action = frontman.FilterActionProxy
		case "ACCEPT":
			result.Action = frontman.FilterActionAllow
		case "DROP":
			result.Action = frontman.FilterActionBlock
		case "MARK":
			i++
			if i >= len(*actionOpt) {
				return nil, errors.New("rulespec not valid: no mark given")
			}
			result.Mark, err = strconv.Atoi((*actionOpt)[i])
			if err != nil {
				return nil, errors.New("rulespec not valid: mark should be int32")
			}
		case "NFLOG":
			// if no other action specified, it will default to 'continue' action (zero)
			result.Log = true
			result.LogPrefix = *logPrefixOpt
			result.GroupID = *groupIDOpt
		default:
			return nil, errors.New("rulespec not valid: invalid action")
		}
	}
	if result.Mark == 0 && (result.Action == frontman.FilterActionNfq || result.Action == frontman.FilterActionForceNfq) {
		return nil, errors.New("rulespec not valid: nfq action needs to set mark")
	}

	// redirect port
	result.ProxyPort = *redirectPortOpt
	if result.Action == frontman.FilterActionProxy && result.ProxyPort == 0 {
		return nil, errors.New("rulespec not valid: no redirect port given")
	}

	return result, nil
}

// Equal compares a WindowsRuleMatchSet to another for equality
func (w *WindowsRuleMatchSet) Equal(other *WindowsRuleMatchSet) bool {
	if other == nil {
		return false
	}
	return w.MatchSetName == other.MatchSetName &&
		w.MatchSetNegate == other.MatchSetNegate &&
		w.MatchSetDstIP == other.MatchSetDstIP &&
		w.MatchSetDstPort == other.MatchSetDstPort &&
		w.MatchSetSrcIP == other.MatchSetSrcIP &&
		w.MatchSetSrcPort == other.MatchSetSrcPort
}

// Equal compares a WindowsRulePortRange to another for equality
func (w *WindowsRulePortRange) Equal(other *WindowsRulePortRange) bool {
	if other == nil {
		return false
	}
	return w.PortStart == other.PortStart && w.PortEnd == other.PortEnd
}

// Equal compares a WindowsRuleSpec to another for equality
func (w *WindowsRuleSpec) Equal(other *WindowsRuleSpec) bool {
	if other == nil {
		return false
	}
	equalSoFar := w.Protocol == other.Protocol &&
		w.Action == other.Action &&
		w.ProxyPort == other.ProxyPort &&
		w.Mark == other.Mark &&
		w.Log == other.Log &&
		w.LogPrefix == other.LogPrefix &&
		w.GroupID == other.GroupID &&
		w.MatchBytesOffset == other.MatchBytesOffset &&
		bytes.Equal(w.MatchBytes, other.MatchBytes) &&
		len(w.MatchSrcPort) == len(other.MatchSrcPort) &&
		len(w.MatchDstPort) == len(other.MatchDstPort) &&
		len(w.MatchSet) == len(other.MatchSet)
	if !equalSoFar {
		return false
	}
	// we checked lengths above, but now continue to compare slices for equality.
	// note: we assume equal slices have elements in the same order.
	for i := 0; i < len(w.MatchSrcPort); i++ {
		if w.MatchSrcPort[i] == nil {
			if other.MatchSrcPort[i] != nil {
				return false
			}
			continue
		}
		if !w.MatchSrcPort[i].Equal(other.MatchSrcPort[i]) {
			return false
		}
	}
	for i := 0; i < len(w.MatchDstPort); i++ {
		if w.MatchDstPort[i] == nil {
			if other.MatchDstPort[i] != nil {
				return false
			}
			continue
		}
		if !w.MatchDstPort[i].Equal(other.MatchDstPort[i]) {
			return false
		}
	}
	for i := 0; i < len(w.MatchSet); i++ {
		if w.MatchSet[i] == nil {
			if other.MatchSet[i] != nil {
				return false
			}
			continue
		}
		if !w.MatchSet[i].Equal(other.MatchSet[i]) {
			return false
		}
	}
	return true
}
