// +build windows

package provider

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"golang.org/x/sys/windows"
)

type RuleCleanup interface {
	MapIpsetToRule(ipsetName string, filterName, criteriaName string)
	DeleteRulesForIpset(ipsetName string) error
	DeleteRuleForIpsetByPrefix(prefix string) error
	DeleteRuleFromIpsetMap(filterName, criteriaName string)
	GetRulesForIpset(ipsetName string) []*filterRulePair
}

type ruleCleaner struct {
	ipsetToRule map[string][]*filterRulePair
}

type filterRulePair struct {
	filterName   string
	ruleCriteria string
}

var ruleCleanerInstance = &ruleCleaner{
	ipsetToRule: make(map[string][]*filterRulePair),
}

func RuleCleanupInstance() RuleCleanup {
	return ruleCleanerInstance
}

// We keep a map of ipset name to rules. This is a safeguard to ensure that rules are deleted.
// Normally, during policy update, rules and ipsets are deleted explicitly and all works well.
// There are some instances though (Discovery Mode) where criteria name strings use in deletion
// do not align with criteria name strings used during addition. This will result in rules
// stranded in our driver, which is really bad for multiple reasons.
// Since deletion of ipsets is more orderly than deletion of rules by criteria name, and since
// the rules that are subject to being stranded are all so far associated with an ephemeral ipset,
// we can use the deletion of an ipset to trigger a cleanup of all rules associated with it.

func (r *ruleCleaner) MapIpsetToRule(ipsetName string, filterName, criteriaName string) {
	r.ipsetToRule[ipsetName] = append(r.ipsetToRule[ipsetName], &filterRulePair{filterName: filterName, ruleCriteria: criteriaName})
}

func (r *ruleCleaner) DeleteRulesForIpset(ipsetName string) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	for _, frpair := range r.ipsetToRule[ipsetName] {
		dllRet, _, err := frontman.DeleteFilterCriteriaProc.Call(driverHandle,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(frpair.filterName))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(frpair.ruleCriteria))))
		if dllRet == 0 {
			return fmt.Errorf("DeleteRulesForIpset failed while deleting %s %v", ipsetName, err)
		}
	}
	delete(r.ipsetToRule, ipsetName)
	return nil
}

// listIpsets is the same code as in Windows ipsetprovider TODO common-ize the code
func (r *ruleCleaner) listIpsets(prefix string) ([]string, error) {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to get driver handle: %v", err)
	}
	// first query for needed buffer size
	var bytesNeeded, ignore uint32
	dllRet, _, err := frontman.ListIpsetsProc.Call(driverHandle, 0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if dllRet != 0 && bytesNeeded == 0 {
		return []string{}, nil
	}
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("%s failed: %v", frontman.ListIpsetsProc.Name, err)
	}
	if bytesNeeded%2 != 0 {
		return nil, fmt.Errorf("%s failed: odd result (%d)", frontman.ListIpsetsProc.Name, bytesNeeded)
	}
	// then allocate buffer for wide string and call again
	buf := make([]uint16, bytesNeeded/2)
	dllRet, _, err = frontman.ListIpsetsProc.Call(driverHandle, uintptr(unsafe.Pointer(&buf[0])), uintptr(bytesNeeded), uintptr(unsafe.Pointer(&ignore)))
	if dllRet == 0 {
		return nil, fmt.Errorf("%s failed (ret=%d err=%v)", frontman.ListIpsetsProc.Name, dllRet, err)
	}
	str := syscall.UTF16ToString(buf)
	ipsets := strings.Split(str, ",")
	return ipsets, nil
}

func (r *ruleCleaner) DeleteRuleForIpsetByPrefix(prefix string) error {

	ipsets, err := r.listIpsets(prefix)
	if err != nil {
		return err
	}
	for _, ipsetName := range ipsets {
		if strings.HasPrefix(ipsetName, prefix) {
			if err := r.DeleteRulesForIpset(ipsetName); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *ruleCleaner) DeleteRuleFromIpsetMap(filterName, criteriaName string) {
	// quadratic for now, optimize later if we need to
	for ipsetName, frpairs := range r.ipsetToRule {
		for i, frpair := range frpairs {
			if frpair.filterName == filterName && frpair.ruleCriteria == criteriaName {
				// delete pair from slice
				frpairs[i] = frpairs[len(frpairs)-1]
				r.ipsetToRule[ipsetName] = frpairs[:len(frpairs)-1]
				// rule can be mapped from multiple ipsets, so continue our outer loop
				break
			}
		}
	}
}

func (r *ruleCleaner) GetRulesForIpset(ipsetName string) []*filterRulePair {
	frpairs := r.ipsetToRule[ipsetName]
	result := make([]*filterRulePair, len(frpairs))
	copy(result, frpairs)
	return result
}
