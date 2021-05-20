// +build windows

package provider

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"syscall"
	"unsafe"

	winipt "go.aporeto.io/enforcerd/trireme-lib/controller/internal/windows"
	"go.aporeto.io/enforcerd/trireme-lib/utils/frontman"
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
	// ResetRules resets the rules to a state where rules with the substring subs are removed
	ResetRules(subs string) error
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
	// ListRules lists the rules in the table/chain passed to it
	ListRules(table, chain string) ([]string, error)
}

// BatchProvider uses iptables-restore to program ACLs
type BatchProvider struct {
	ipv4 bool
}

// NewGoIPTablesProviderV4 returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProviderV4(batchTables []string, customChain string) (IptablesProvider, error) {
	return &BatchProvider{ipv4: true}, nil
}

// NewGoIPTablesProviderV6 returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProviderV6(batchTables []string, customChain string) (IptablesProvider, error) {
	return &BatchProvider{ipv4: false}, nil
}

// NewCustomBatchProvider is a custom batch provider wher the downstream
// iptables utility is provided by the caller. Very useful for testing
// the ACL functions with a mock.
func NewCustomBatchProvider(ipt BaseIPTables, commit func(buf *bytes.Buffer) error, batchTables []string) *BatchProvider {
	return &BatchProvider{ipv4: true}
}

// helper function for passing args to frontman api
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

const ipv4ChainSuffix = "-v4"
const ipv6ChainSuffix = "-v6"

func (b *BatchProvider) fixChainName(chain string) string {
	if strings.HasSuffix(chain, ipv4ChainSuffix) || strings.HasSuffix(chain, ipv6ChainSuffix) {
		return chain
	}
	if b.ipv4 {
		chain += ipv4ChainSuffix
	} else {
		chain += ipv6ChainSuffix
	}
	return chain
}

func (b *BatchProvider) fixRuleSpec(rulespec []string) []string {
	// When a rule is referencing another chain, then we need to add the IP version number.
	length := len(rulespec)
	for index, part := range rulespec {
		nextIndex := index + 1
		if part == "-j" && nextIndex < length {
			switch rulespec[nextIndex] {
			case "NFQUEUE":
			case "NFQUEUE_FORCE":
			case "REDIRECT":
			case "ACCEPT":
			case "ACCEPT_ONCE":
			case "DROP":
			case "MARK":
			case "CONNMARK":
			case "NFLOG":
			default:
				rulespec[nextIndex] = b.fixChainName(rulespec[nextIndex])
			}
		}
	}
	return rulespec
}

// Append will append the provided rule to the local cache or call
// directly the iptables command depending on the table.
func (b *BatchProvider) Append(table, chain string, rulespec ...string) error {

	chain = b.fixChainName(chain)
	rulespec = b.fixRuleSpec(rulespec)

	zap.L().Debug(fmt.Sprintf("add rule %s to table/chain %s/%s", strings.Join(rulespec, " "), table, chain))

	winRuleSpec, err := winipt.ParseRuleSpec(rulespec...)
	if err != nil {
		return err
	}

	criteriaID := strings.Join(rulespec, " ")

	argRuleSpec := frontman.RuleSpec{
		Action:    uint8(winRuleSpec.Action),
		Log:       boolToUint8(winRuleSpec.Log),
		GroupID:   uint32(winRuleSpec.GroupID),
		ProxyPort: uint16(winRuleSpec.ProxyPort),
		Mark:      uint32(winRuleSpec.Mark),
		ProcessID: uint64(winRuleSpec.ProcessID),
	}

	if b.ipv4 {
		argRuleSpec.IPVersionMatch = frontman.IPVersion4
	} else {
		argRuleSpec.IPVersionMatch = frontman.IPVersion6
	}

	if winRuleSpec.FlowMark != 0 {
		argRuleSpec.FlowMark = uint32(winRuleSpec.FlowMark)
		if winRuleSpec.FlowMarkNoMatch {
			argRuleSpec.FlowMarkMatchType = frontman.MatchTypeNoMatch
		} else {
			argRuleSpec.FlowMarkMatchType = frontman.MatchTypeMatch
		}
	}

	if winRuleSpec.TCPFlagsSpecified {
		argRuleSpec.TCPFlagsSpecified = 1
		argRuleSpec.TCPFlags = winRuleSpec.TCPFlags
		argRuleSpec.TCPFlagsMask = winRuleSpec.TCPFlagsMask
	}

	if winRuleSpec.TCPOptionSpecified {
		argRuleSpec.TCPOptionSpecified = 1
		argRuleSpec.TCPOption = winRuleSpec.TCPOption
	}

	if winRuleSpec.Protocol > 0 && winRuleSpec.Protocol < math.MaxUint8 {
		argRuleSpec.ProtocolSpecified = 1
		argRuleSpec.Protocol = uint8(winRuleSpec.Protocol)
	}
	if len(winRuleSpec.MatchSrcPort) > 0 {
		argRuleSpec.SrcPortCount = int32(len(winRuleSpec.MatchSrcPort))
		srcPorts := make([]frontman.PortRange, argRuleSpec.SrcPortCount)
		for i, portRange := range winRuleSpec.MatchSrcPort {
			srcPorts[i] = frontman.PortRange{PortStart: uint16(portRange.Start), PortEnd: uint16(portRange.End)}
		}
		argRuleSpec.SrcPorts = &srcPorts[0]
	}
	if len(winRuleSpec.MatchDstPort) > 0 {
		argRuleSpec.DstPortCount = int32(len(winRuleSpec.MatchDstPort))
		dstPorts := make([]frontman.PortRange, argRuleSpec.DstPortCount)
		for i, portRange := range winRuleSpec.MatchDstPort {
			dstPorts[i] = frontman.PortRange{PortStart: uint16(portRange.Start), PortEnd: uint16(portRange.End)}
		}
		argRuleSpec.DstPorts = &dstPorts[0]
	}
	if len(winRuleSpec.MatchBytes) > 0 {
		if winRuleSpec.MatchBytesNoMatch {
			argRuleSpec.BytesNoMatch = 1
		}
		argRuleSpec.BytesMatchStart = frontman.BytesMatchStartPayload
		argRuleSpec.BytesMatchOffset = int32(winRuleSpec.MatchBytesOffset)
		argRuleSpec.BytesMatchSize = int32(len(winRuleSpec.MatchBytes))
		argRuleSpec.BytesMatch = &winRuleSpec.MatchBytes[0]
	}
	if winRuleSpec.LogPrefix != "" {
		argRuleSpec.LogPrefix = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(winRuleSpec.LogPrefix))) // nolint:staticcheck
	}
	if winRuleSpec.ProcessID > 0 {
		if winRuleSpec.ProcessIncludeChildrenOnly {
			argRuleSpec.ProcessFlags = frontman.ProcessMatchChildren
		} else {
			argRuleSpec.ProcessFlags = frontman.ProcessMatchProcess
			if winRuleSpec.ProcessIncludeChildren {
				argRuleSpec.ProcessFlags |= frontman.ProcessMatchChildren
			}
		}
	}
	if len(winRuleSpec.IcmpMatch) > 0 {
		argRuleSpec.IcmpRangeCount = int32(len(winRuleSpec.IcmpMatch))
		icmpRanges := make([]frontman.IcmpRange, argRuleSpec.IcmpRangeCount)
		for i, im := range winRuleSpec.IcmpMatch {
			r := frontman.IcmpRange{}
			if !im.Nomatch {
				r.IcmpTypeSpecified = 1
				r.IcmpType = uint8(im.IcmpType)
				if im.IcmpCodeRange != nil {
					r.IcmpCodeSpecified = 1
					r.IcmpCodeLower = uint8(im.IcmpCodeRange.Start)
					r.IcmpCodeUpper = uint8(im.IcmpCodeRange.End)
				}
			}
			icmpRanges[i] = r
		}
		argRuleSpec.IcmpRanges = &icmpRanges[0]
	}
	argIpsetRuleSpecs := make([]frontman.IpsetRuleSpec, len(winRuleSpec.MatchSet))
	for i, matchSet := range winRuleSpec.MatchSet {
		argIpsetRuleSpecs[i].NotIpset = boolToUint8(matchSet.MatchSetNegate)
		argIpsetRuleSpecs[i].IpsetDstIP = boolToUint8(matchSet.MatchSetDstIP)
		argIpsetRuleSpecs[i].IpsetDstPort = boolToUint8(matchSet.MatchSetDstPort)
		argIpsetRuleSpecs[i].IpsetSrcIP = boolToUint8(matchSet.MatchSetSrcIP)
		argIpsetRuleSpecs[i].IpsetSrcPort = boolToUint8(matchSet.MatchSetSrcPort)
		argIpsetRuleSpecs[i].IpsetName = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(matchSet.MatchSetName))) // nolint:staticcheck
	}

	if winRuleSpec.GotoFilterName != "" {
		argRuleSpec.GotoFilterName = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(winRuleSpec.GotoFilterName))) // nolint:staticcheck
	}

	return frontman.Wrapper.AppendFilterCriteria(chain, criteriaID, &argRuleSpec, argIpsetRuleSpecs)
}

// Insert will insert the rule in the corresponding position in the local
// cache or call the corresponding iptables command, depending on the table.
func (b *BatchProvider) Insert(table, chain string, pos int, rulespec ...string) error {
	chain = b.fixChainName(chain)
	zap.L().Debug(fmt.Sprintf("Insert not expected for table %s and chain %s", table, chain))
	return nil
}

// Delete will delete the rule from the local cache or the system.
func (b *BatchProvider) Delete(table, chain string, rulespec ...string) error {
	chain = b.fixChainName(chain)
	rulespec = b.fixRuleSpec(rulespec)
	criteriaID := strings.Join(rulespec, " ")
	zap.L().Debug(fmt.Sprintf("delete rule %s from table/chain %s/%s", criteriaID, table, chain))
	return frontman.Wrapper.DeleteFilterCriteria(chain, criteriaID)
}

// ListChains will provide a list of the current chains.
func (b *BatchProvider) ListChains(table string) ([]string, error) {
	var outbound bool
	if strings.HasPrefix(table, "O") || strings.HasPrefix(table, "o") {
		outbound = true
	} else if strings.HasPrefix(table, "I") || strings.HasPrefix(table, "i") {
		outbound = false
	} else {
		return nil, fmt.Errorf("'%s' is not a valid table for ListChains", table)
	}

	return frontman.Wrapper.GetFilterList(outbound)
}

// ClearChain will clear the chains.
func (b *BatchProvider) ClearChain(table, chain string) error {
	chain = b.fixChainName(chain)
	return frontman.Wrapper.EmptyFilter(chain)
}

// DeleteChain will delete the chains.
func (b *BatchProvider) DeleteChain(table, chain string) error {
	chain = b.fixChainName(chain)
	return frontman.Wrapper.DestroyFilter(chain)
}

// NewChain creates a new chain.
func (b *BatchProvider) NewChain(table, chain string) error {
	chain = b.fixChainName(chain)
	var outbound bool
	if strings.HasPrefix(table, "O") || strings.HasPrefix(table, "o") {
		outbound = true
	} else if strings.HasPrefix(table, "I") || strings.HasPrefix(table, "i") {
		outbound = false
	} else {
		return fmt.Errorf("'%s' is not a valid table for NewChain", table)
	}

	// A goto filter is outside the normal filters and a rule can jump to a "goto filter"
	// So any filter that has -Net or -App is a goto filter.
	isGotoFilter := false
	if strings.Contains(chain, "-Net") || strings.Contains(chain, "-App") {
		isGotoFilter = true
	}
	return frontman.Wrapper.AppendFilter(outbound, chain, isGotoFilter)
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

// ResetRules returns nil in windows
func (b *BatchProvider) ResetRules(subs string) error {
	// does nothing
	return nil
}

// ListRules lists the rules in the table/chain passed to it
func (b *BatchProvider) ListRules(table, chain string) ([]string, error) {
	// This is is unimplemented on windows
	return []string{}, nil
}
