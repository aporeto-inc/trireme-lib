// +build windows

package windows

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/DavidGamba/go-getoptions"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
)

// structure representing result of parsed --match-set
type WindowsRuleMatchSet struct {
	MatchSetName    string
	MatchSetNegate  bool
	MatchSetDstIp   bool
	MatchSetDstPort bool
	MatchSetSrcIp   bool
	MatchSetSrcPort bool
}

// structure representing parsed port range
type WindowsRulePortRange struct {
	PortStart int
	PortEnd   int
}

// structure representing result of parsed iptables rule
type WindowsRuleSpec struct {
	Protocol         int
	Action           int // FilterAction (allow, drop, nfq, proxy)
	ProxyPort        int
	Mark             int
	Log              bool
	LogPrefix        string
	GroupId          int
	MatchSrcPort     []*WindowsRulePortRange
	MatchDstPort     []*WindowsRulePortRange
	MatchBytes       []byte
	MatchBytesOffset int
	MatchSet         []*WindowsRuleMatchSet
}

// converts a WindowsRuleSpec back into a string for an iptables rule
func MakeRuleSpecText(winRuleSpec *WindowsRuleSpec) string {
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
			if ms.MatchSetSrcIp {
				rulespec += "srcIP"
				if ms.MatchSetSrcPort || ms.MatchSetDstPort {
					rulespec += ","
				}
			} else if ms.MatchSetDstIp {
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
	}
	if winRuleSpec.Log {
		rulespec += fmt.Sprintf("-j NFLOG --nflog-group %d --nflog-prefix %s ", winRuleSpec.GroupId, winRuleSpec.LogPrefix)
	}
	return strings.TrimSpace(rulespec)
}

// parse comma-separated list of port or port ranges
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
	groupIdOpt := opt.Int("nflog-group", 0)
	logPrefixOpt := opt.String("nflog-prefix", "")

	_, err := opt.Parse(rulespec)
	if err != nil {
		return nil, err
	}

	result := &WindowsRuleSpec{}

	// protocol
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
				matchSet.MatchSetDstIp = true
			} else if strings.HasPrefix(ipPortSpecLower, "srcip") {
				matchSet.MatchSetSrcIp = true
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
			if !matchSet.MatchSetDstIp && !matchSet.MatchSetDstPort && !matchSet.MatchSetSrcIp && !matchSet.MatchSetSrcPort {
				// look for acl-created iptables-conforming match on 'dst' or 'src'.
				// a dst or src by itself we take to mean match both. otherwise, we take it as ip-match,port-match.
				if strings.HasPrefix(ipPortSpecLower, "dst") {
					matchSet.MatchSetDstIp = true
				} else if strings.HasPrefix(ipPortSpecLower, "src") {
					matchSet.MatchSetSrcIp = true
				}
				if strings.HasSuffix(ipPortSpecLower, "dst") {
					matchSet.MatchSetDstPort = true
					if result.Protocol < 1 {
						return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
					}
				} else if strings.HasSuffix(ipPortSpecLower, "src") {
					matchSet.MatchSetSrcPort = true
					if result.Protocol < 1 {
						return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
					}
				}
			}
			if !matchSet.MatchSetDstIp && !matchSet.MatchSetDstPort && !matchSet.MatchSetSrcIp && !matchSet.MatchSetSrcPort {
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
			break

		default:
			return nil, errors.New("rulespec not valid: unknown -m option")
		}
	}

	// action: either NFQUEUE, REDIRECT, MARK, ACCEPT, DROP, NFLOG
	for i := 0; i < len(*actionOpt); i++ {
		switch (*actionOpt)[i] {
		case "NFQUEUE":
			result.Action = frontman.FilterActionNfq
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
			result.Log = true
			result.LogPrefix = *logPrefixOpt
			result.GroupId = *groupIdOpt
		default:
			return nil, errors.New("rulespec not valid: invalid action")
		}
	}
	if result.Action == frontman.FilterActionNfq && result.Mark == 0 {
		return nil, errors.New("rulespec not valid: nfq action needs to set mark")
	}

	// redirect port
	result.ProxyPort = *redirectPortOpt
	if result.Action == frontman.FilterActionProxy && result.ProxyPort == 0 {
		return nil, errors.New("rulespec not valid: no redirect port given")
	}

	return result, nil
}
