// +build windows

package provider

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"golang.org/x/sys/windows"

	"github.com/DavidGamba/go-getoptions"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.uber.org/zap"
)

// IptablesProvider is an abstraction of all the methods an implementation of userspace
// iptables need to provide.
type IptablesProvider interface {
	BaseIPTables
	// Commit will commit changes if it is a batch provider.
	Commit() error
	// RetrieveTable allows a caller to retrieve the final table.
	RetrieveTable() map[string]map[string][]string
}

// BaseIPTables is the base interface of iptables functions.
type BaseIPTables interface {
	// Append apends a rule to chain of table
	Append(table, chain string, rulespec ...string) error
	// Insert inserts a rule to a chain of table at the required pos
	Insert(table, chain string, pos int, rulespec ...string) error
	// Delete deletes a rule of a chain in the given table
	Delete(table, chain string, rulespec ...string) error
	// ListChains lists all the chains associated with a table
	ListChains(table string) ([]string, error)
	// ClearChain clears a chain in a table
	ClearChain(table, chain string) error
	// DeleteChain deletes a chain in the table. There should be no references to this chain
	DeleteChain(table, chain string) error
	// NewChain creates a new chain
	NewChain(table, chain string) error
}

// BatchProvider uses iptables-restore to program ACLs
type BatchProvider struct {
}

// NewGoIPTablesProviderV4 returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProviderV4(batchTables []string) (*BatchProvider, error) {
	return &BatchProvider{}, nil
}

// NewGoIPTablesProviderV6 returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProviderV6(batchTables []string) (*BatchProvider, error) {
	return &BatchProvider{}, nil
}

// NewCustomBatchProvider is a custom batch provider wher the downstream
// iptables utility is provided by the caller. Very useful for testing
// the ACL functions with a mock.
func NewCustomBatchProvider(ipt BaseIPTables, commit func(buf *bytes.Buffer) error, batchTables []string) *BatchProvider {
	return &BatchProvider{}
}

// private structure representing result of parsed --match-set
type windowsRuleMatchSet struct {
	matchSetName    string
	matchSetNegate  bool
	matchSetDstIp   bool
	matchSetDstPort bool
	matchSetSrcIp   bool
	matchSetSrcPort bool
}

// private structure representing parsed port range
type windowsRulePortRange struct {
	portStart int
	portEnd   int
}

// private structure representing result of parsed iptables rule
type windowsRuleSpec struct {
	protocol         int
	action           int // FilterAction (allow, drop, nfq, proxy)
	proxyPort        int
	mark             int
	log              bool
	logPrefix        string
	groupId          int
	matchSrcPort     []*windowsRulePortRange
	matchDstPort     []*windowsRulePortRange
	matchBytes       []byte
	matchBytesOffset int
	matchSet         []*windowsRuleMatchSet
}

// parseRuleSpec parses a windows iptable rule
func parseRuleSpec(rulespec ...string) (*windowsRuleSpec, error) {

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
	opt.String("state", "")   // "--state NEW" et al ignored
	opt.String("match", "")   // "--match multiport" ignored
	opt.Int("nflog-group", 0) // ignored
	logPrefixOpt := opt.String("nflog-prefix", "")

	_, err := opt.Parse(rulespec)
	if err != nil {
		return nil, err
	}

	result := &windowsRuleSpec{}

	// protocol
	switch strings.ToLower(*protocolOpt) {
	case "tcp":
		result.protocol = packet.IPProtocolTCP
	case "udp":
		result.protocol = packet.IPProtocolUDP
	case "icmp":
		result.protocol = 1
	case "": // not specified = all
		fallthrough
	case "all":
		result.protocol = -1
	default:
		result.protocol, err = strconv.Atoi(*protocolOpt)
		if err != nil {
			return nil, errors.New("rulespec not valid: invalid protocol")
		}
		if result.protocol < 0 || result.protocol > math.MaxUint8 {
			return nil, errors.New("rulespec not valid: invalid protocol")
		}
		// iptables man page says protocol zero is equivalent to 'all' (sorry, IPv6 Hop-by-Hop Option)
		if result.protocol == 0 {
			result.protocol = -1
		}
	}

	// src/dest port: either port or port range or list of such
	for i, portOpt := range []string{*sPortOpt, *dPortOpt} {
		if portOpt != "" {
			portList := strings.Split(portOpt, ",")
			for _, portListItem := range portList {
				portEnd := 0
				portStart, err := strconv.Atoi(portListItem)
				if err != nil {
					portRange := strings.SplitN(portListItem, ":", 2)
					if len(portRange) != 2 {
						return nil, errors.New("rulespec not valid: invalid match port")
					}
					portStart, err = strconv.Atoi(portRange[0])
					if err != nil {
						return nil, errors.New("rulespec not valid: invalid match port")
					}
					portEnd, err = strconv.Atoi(portRange[1])
					if err != nil {
						return nil, errors.New("rulespec not valid: invalid match port")
					}
				}
				if portEnd == 0 {
					portEnd = portStart
				}
				if i == 0 {
					result.matchSrcPort = append(result.matchSrcPort, &windowsRulePortRange{portStart, portEnd})
				} else {
					result.matchDstPort = append(result.matchDstPort, &windowsRulePortRange{portStart, portEnd})
				}
			}
		}
	}

	// match ipset
	for i, modeOptSetNum := 0, 0; i < len(*modeOpt); i++ {
		switch (*modeOpt)[i] {
		case "set":
			matchSet := &windowsRuleMatchSet{}
			// see if negate of --match-set occurred
			if i+1 < len(*modeOpt) && (*modeOpt)[i+1] == "!" {
				matchSet.matchSetNegate = true
				i++
			}
			// now check corresponding match-set by index
			matchSetIndex := 2 * modeOptSetNum
			modeOptSetNum++
			if matchSetIndex+1 >= len(*matchSetOpt) {
				return nil, errors.New("rulespec not valid: --match-set not found for -m set")
			}
			// first part is the ipset name
			matchSet.matchSetName = (*matchSetOpt)[matchSetIndex]
			// second part is the dst/src match specifier
			ipPortSpecLower := strings.ToLower((*matchSetOpt)[matchSetIndex+1])
			if strings.HasPrefix(ipPortSpecLower, "dstip") {
				matchSet.matchSetDstIp = true
			} else if strings.HasPrefix(ipPortSpecLower, "srcip") {
				matchSet.matchSetSrcIp = true
			}
			if strings.HasSuffix(ipPortSpecLower, "dstport") {
				matchSet.matchSetDstPort = true
				if result.protocol < 1 {
					return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
				}
			} else if strings.HasSuffix(ipPortSpecLower, "srcport") {
				matchSet.matchSetSrcPort = true
				if result.protocol < 1 {
					return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
				}
			}
			if !matchSet.matchSetDstIp && !matchSet.matchSetDstPort && !matchSet.matchSetSrcIp && !matchSet.matchSetSrcPort {
				// look for acl-created iptables-conforming match on 'dst' or 'src'.
				// a dst or src by itself we take to mean match both. otherwise, we take it as ip-match,port-match.
				if strings.HasPrefix(ipPortSpecLower, "dst") {
					matchSet.matchSetDstIp = true
				} else if strings.HasPrefix(ipPortSpecLower, "src") {
					matchSet.matchSetSrcIp = true
				}
				if strings.HasSuffix(ipPortSpecLower, "dst") {
					matchSet.matchSetDstPort = true
					if result.protocol < 1 {
						return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
					}
				} else if strings.HasSuffix(ipPortSpecLower, "src") {
					matchSet.matchSetSrcPort = true
					if result.protocol < 1 {
						return nil, errors.New("rulespec not valid: ipset match on port requires protocol be set")
					}
				}
			}
			if !matchSet.matchSetDstIp && !matchSet.matchSetDstPort && !matchSet.matchSetSrcIp && !matchSet.matchSetSrcPort {
				return nil, errors.New("rulespec not valid: ipset match needs ip/port specifier")
			}
			result.matchSet = append(result.matchSet, matchSet)

		case "string":
			if *matchStringOpt == "" {
				return nil, errors.New("rulespec not valid: no match string given")
			}
			result.matchBytes = []byte(*matchStringOpt)
			result.matchBytesOffset = *matchStringOffsetOpt

		case "state":
			// for "-m state --state NEW"
			// skip it for now
			break

		default:
			return nil, errors.New("rulespec not valid: unknown -m option")
		}
	}

	// action: required, either NFQUEUE, REDIRECT, MARK, ACCEPT, DROP, NFLOG
	for i := 0; i < len(*actionOpt); i++ {
		switch (*actionOpt)[i] {
		case "NFQUEUE":
			result.action = frontman.FilterActionNfq
		case "REDIRECT":
			result.action = frontman.FilterActionProxy
		case "ACCEPT":
			result.action = frontman.FilterActionAllow
		case "DROP":
			result.action = frontman.FilterActionBlock
		case "MARK":
			i++
			if i >= len(*actionOpt) {
				return nil, errors.New("rulespec not valid: no mark given")
			}
			result.mark, err = strconv.Atoi((*actionOpt)[i])
			if err != nil {
				return nil, errors.New("rulespec not valid: mark should be int32")
			}
		case "NFLOG":
			result.log = true
			result.logPrefix = *logPrefixOpt
		default:
			return nil, errors.New("rulespec not valid: invalid action")
		}
	}
	if result.action == frontman.FilterActionNfq && result.mark == 0 {
		return nil, errors.New("rulespec not valid: nfq action needs to set mark")
	}

	// redirect port
	result.proxyPort = *redirectPortOpt
	if result.action == frontman.FilterActionProxy && result.proxyPort == 0 {
		return nil, errors.New("rulespec not valid: no redirect port given")
	}

	return result, nil
}

// helper function for passing args to frontman api
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// Append will append the provided rule to the local cache or call
// directly the iptables command depending on the table.
func (b *BatchProvider) Append(table, chain string, rulespec ...string) error {

	zap.L().Debug(fmt.Sprintf("add rule %s to table/chain %s/%s", strings.Join(rulespec, " "), table, chain))

	winRuleSpec, err := parseRuleSpec(rulespec...)
	if err != nil {
		return err
	}

	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return err
	}

	criteriaId := strings.Join(rulespec, " ")
	argRuleSpec := frontman.RuleSpec{
		Action:    uint8(winRuleSpec.action),
		Log:       boolToUint8(winRuleSpec.log),
		ProxyPort: uint16(winRuleSpec.proxyPort),
		Mark:      uint32(winRuleSpec.mark),
	}
	if winRuleSpec.protocol > 0 && winRuleSpec.protocol < math.MaxUint8 {
		argRuleSpec.ProtocolSpecified = 1
		argRuleSpec.Protocol = uint8(winRuleSpec.protocol)
	}
	if len(winRuleSpec.matchSrcPort) > 0 {
		argRuleSpec.SrcPortCount = int32(len(winRuleSpec.matchSrcPort))
		srcPorts := make([]frontman.PortRange, argRuleSpec.SrcPortCount)
		for i, portRange := range winRuleSpec.matchSrcPort {
			srcPorts[i] = frontman.PortRange{uint16(portRange.portStart), uint16(portRange.portEnd)}
		}
		argRuleSpec.SrcPorts = &srcPorts[0]
	}
	if len(winRuleSpec.matchDstPort) > 0 {
		argRuleSpec.DstPortCount = int32(len(winRuleSpec.matchDstPort))
		dstPorts := make([]frontman.PortRange, argRuleSpec.DstPortCount)
		for i, portRange := range winRuleSpec.matchDstPort {
			dstPorts[i] = frontman.PortRange{uint16(portRange.portStart), uint16(portRange.portEnd)}
		}
		argRuleSpec.DstPorts = &dstPorts[0]
	}
	if len(winRuleSpec.matchBytes) > 0 {
		argRuleSpec.BytesMatchStart = frontman.BytesMatchStartPayload
		argRuleSpec.BytesMatchOffset = int32(winRuleSpec.matchBytesOffset)
		argRuleSpec.BytesMatchSize = int32(len(winRuleSpec.matchBytes))
		argRuleSpec.BytesMatch = &winRuleSpec.matchBytes[0]
	}
	argIpsetRuleSpecs := make([]frontman.IpsetRuleSpec, len(winRuleSpec.matchSet))
	for i, matchSet := range winRuleSpec.matchSet {
		argIpsetRuleSpecs[i].NotIpset = boolToUint8(matchSet.matchSetNegate)
		argIpsetRuleSpecs[i].IpsetDstIp = boolToUint8(matchSet.matchSetDstIp)
		argIpsetRuleSpecs[i].IpsetDstPort = boolToUint8(matchSet.matchSetDstPort)
		argIpsetRuleSpecs[i].IpsetSrcIp = boolToUint8(matchSet.matchSetSrcIp)
		argIpsetRuleSpecs[i].IpsetSrcPort = boolToUint8(matchSet.matchSetSrcPort)
		argIpsetRuleSpecs[i].IpsetName = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(matchSet.matchSetName)))
	}
	var dllRet uintptr
	if len(argIpsetRuleSpecs) > 0 {
		dllRet, _, err = frontman.AppendFilterCriteriaProc.Call(driverHandle,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(chain))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(criteriaId))),
			uintptr(unsafe.Pointer(&argRuleSpec)),
			uintptr(unsafe.Pointer(&argIpsetRuleSpecs[0])),
			uintptr(len(argIpsetRuleSpecs)))
	} else {
		dllRet, _, err = frontman.AppendFilterCriteriaProc.Call(driverHandle,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(chain))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(criteriaId))),
			uintptr(unsafe.Pointer(&argRuleSpec)), 0, 0)
	}

	if dllRet == 0 {
		return fmt.Errorf("%s failed (%v)", frontman.AppendFilterCriteriaProc.Name, err)
	}

	return nil
}

// Insert will insert the rule in the corresponding position in the local
// cache or call the corresponding iptables command, depending on the table.
func (b *BatchProvider) Insert(table, chain string, pos int, rulespec ...string) error {
	zap.L().Debug(fmt.Sprintf("Insert not expected for table %s and chain %s", table, chain))
	return nil
}

// Delete will delete the rule from the local cache or the system.
func (b *BatchProvider) Delete(table, chain string, rulespec ...string) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return err
	}

	criteriaId := strings.Join(rulespec, " ")
	dllRet, _, err := frontman.DeleteFilterCriteriaProc.Call(driverHandle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(chain))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(criteriaId))))

	if dllRet == 0 {
		return fmt.Errorf("%s failed - could not delete %s (%v)", frontman.DeleteFilterCriteriaProc.Name, criteriaId, err)
	}

	return nil
}

// ListChains will provide a list of the current chains.
func (b *BatchProvider) ListChains(table string) ([]string, error) {
	var outbound uintptr
	if strings.HasPrefix(table, "O") || strings.HasPrefix(table, "o") {
		outbound = 1
	} else if strings.HasPrefix(table, "I") || strings.HasPrefix(table, "i") {
		outbound = 0
	} else {
		return nil, fmt.Errorf("'%s' is not a valid table for ListChains", table)
	}

	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return nil, err
	}

	// first query for needed buffer size
	var bytesNeeded, ignore uint32
	dllRet, _, err := frontman.GetFilterListProc.Call(driverHandle, outbound, 0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if dllRet != 0 && bytesNeeded == 0 {
		return []string{}, nil
	}
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("%s failed: %v", frontman.GetFilterListProc.Name, err)
	}
	if bytesNeeded%2 != 0 {
		return nil, fmt.Errorf("%s failed: odd result (%d)", frontman.GetFilterListProc.Name, bytesNeeded)
	}
	// then allocate buffer for wide string and call again
	buf := make([]uint16, bytesNeeded/2)
	dllRet, _, err = frontman.GetFilterListProc.Call(driverHandle, outbound, uintptr(unsafe.Pointer(&buf[0])), uintptr(bytesNeeded), uintptr(unsafe.Pointer(&ignore)))
	if dllRet == 0 {
		return nil, fmt.Errorf("%s failed (ret=%d err=%v)", frontman.GetFilterListProc.Name, dllRet, err)
	}
	str := syscall.UTF16ToString(buf)
	ipsets := strings.Split(str, ",")
	return ipsets, nil
}

// ClearChain will clear the chains.
func (b *BatchProvider) ClearChain(table, chain string) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return err
	}

	dllRet, _, err := frontman.EmptyFilterProc.Call(driverHandle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(chain))))
	if dllRet == 0 {
		return fmt.Errorf("%s failed (%v)", frontman.EmptyFilterProc.Name, err)
	}

	return nil
}

// DeleteChain will delete the chains.
func (b *BatchProvider) DeleteChain(table, chain string) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return err
	}

	dllRet, _, err := frontman.DestroyFilterProc.Call(driverHandle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(chain))))
	if dllRet == 0 {
		return fmt.Errorf("%s failed (%v)", frontman.DestroyFilterProc.Name, err)
	}

	return nil
}

// NewChain creates a new chain.
func (b *BatchProvider) NewChain(table, chain string) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return err
	}

	var outbound uintptr
	if strings.HasPrefix(table, "O") || strings.HasPrefix(table, "o") {
		outbound = 1
	} else if strings.HasPrefix(table, "I") || strings.HasPrefix(table, "i") {
		outbound = 0
	} else {
		return fmt.Errorf("'%s' is not a valid table for NewChain", table)
	}

	dllRet, _, err := frontman.AppendFilterProc.Call(driverHandle, outbound, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(chain))))
	if dllRet == 0 {
		return fmt.Errorf("%s failed (%v)", frontman.AppendFilterProc.Name, err)
	}

	return nil
}

// Commit commits the rules to the system
func (b *BatchProvider) Commit() error {
	// does nothing
	return nil
}

// RetrieveTable allows a caller to retrieve the final table. Mostly
// needed for debuging and unit tests.
func (b *BatchProvider) RetrieveTable() map[string]map[string][]string {
	// not applicable for windows
	return map[string]map[string][]string{}
}
