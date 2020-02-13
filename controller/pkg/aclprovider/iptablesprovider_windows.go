// +build windows

package provider

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	winipt "go.aporeto.io/trireme-lib/controller/internal/windows"
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
func NewGoIPTablesProviderV4(batchTables []string) (IptablesProvider, error) {
	return &BatchProvider{}, nil
}

// NewGoIPTablesProviderV6 returns an IptablesProvider interface based on the go-iptables
// external package.
func NewGoIPTablesProviderV6(batchTables []string) (IptablesProvider, error) {
	return &BatchProvider{}, nil
}

// NewCustomBatchProvider is a custom batch provider wher the downstream
// iptables utility is provided by the caller. Very useful for testing
// the ACL functions with a mock.
func NewCustomBatchProvider(ipt BaseIPTables, commit func(buf *bytes.Buffer) error, batchTables []string) *BatchProvider {
	return &BatchProvider{}
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

	winRuleSpec, err := winipt.ParseRuleSpec(rulespec...)
	if err != nil {
		return err
	}

	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return err
	}

	criteriaId := strings.Join(rulespec, " ")
	argRuleSpec := frontman.RuleSpec{
		Action:    uint8(winRuleSpec.Action),
		Log:       boolToUint8(winRuleSpec.Log),
		GroupId:   uint32(winRuleSpec.GroupId),
		ProxyPort: uint16(winRuleSpec.ProxyPort),
		Mark:      uint32(winRuleSpec.Mark),
		ProcessId: uint64(winRuleSpec.ProcessId),
	}
	if winRuleSpec.Protocol > 0 && winRuleSpec.Protocol < math.MaxUint8 {
		argRuleSpec.ProtocolSpecified = 1
		argRuleSpec.Protocol = uint8(winRuleSpec.Protocol)
	}
	if len(winRuleSpec.MatchSrcPort) > 0 {
		argRuleSpec.SrcPortCount = int32(len(winRuleSpec.MatchSrcPort))
		srcPorts := make([]frontman.PortRange, argRuleSpec.SrcPortCount)
		for i, portRange := range winRuleSpec.MatchSrcPort {
			srcPorts[i] = frontman.PortRange{uint16(portRange.PortStart), uint16(portRange.PortEnd)}
		}
		argRuleSpec.SrcPorts = &srcPorts[0]
	}
	if len(winRuleSpec.MatchDstPort) > 0 {
		argRuleSpec.DstPortCount = int32(len(winRuleSpec.MatchDstPort))
		dstPorts := make([]frontman.PortRange, argRuleSpec.DstPortCount)
		for i, portRange := range winRuleSpec.MatchDstPort {
			dstPorts[i] = frontman.PortRange{uint16(portRange.PortStart), uint16(portRange.PortEnd)}
		}
		argRuleSpec.DstPorts = &dstPorts[0]
	}
	if len(winRuleSpec.MatchBytes) > 0 {
		argRuleSpec.BytesMatchStart = frontman.BytesMatchStartPayload
		argRuleSpec.BytesMatchOffset = int32(winRuleSpec.MatchBytesOffset)
		argRuleSpec.BytesMatchSize = int32(len(winRuleSpec.MatchBytes))
		argRuleSpec.BytesMatch = &winRuleSpec.MatchBytes[0]
	}
	if winRuleSpec.LogPrefix != "" {
		argRuleSpec.LogPrefix = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(winRuleSpec.LogPrefix)))
	}
	argIpsetRuleSpecs := make([]frontman.IpsetRuleSpec, len(winRuleSpec.MatchSet))
	for i, matchSet := range winRuleSpec.MatchSet {
		argIpsetRuleSpecs[i].NotIpset = boolToUint8(matchSet.MatchSetNegate)
		argIpsetRuleSpecs[i].IpsetDstIp = boolToUint8(matchSet.MatchSetDstIp)
		argIpsetRuleSpecs[i].IpsetDstPort = boolToUint8(matchSet.MatchSetDstPort)
		argIpsetRuleSpecs[i].IpsetSrcIp = boolToUint8(matchSet.MatchSetSrcIp)
		argIpsetRuleSpecs[i].IpsetSrcPort = boolToUint8(matchSet.MatchSetSrcPort)
		argIpsetRuleSpecs[i].IpsetName = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(matchSet.MatchSetName)))
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
