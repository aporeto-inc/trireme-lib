// +build windows

package frontman

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WrapDriver represents convenience wrapper methods for calling our Windows Frontman DLL
type WrapDriver interface {
	GetDestInfo(socket uintptr, destInfo *DestInfo) error
	ApplyDestHandle(socket, destHandle uintptr) error
	FreeDestHandle(destHandle uintptr) error
	NewIpset(name, ipsetType string) (uintptr, error)
	GetIpset(name string) (uintptr, error)
	DestroyAllIpsets(prefix string) error
	ListIpsets() ([]string, error)
	ListIpsetsDetail(format int) (string, error)
	IpsetAdd(ipsetHandle uintptr, entry string, timeout int) error
	IpsetAddOption(ipsetHandle uintptr, entry, option string, timeout int) error
	IpsetDelete(ipsetHandle uintptr, entry string) error
	IpsetDestroy(ipsetHandle uintptr) error
	IpsetFlush(ipsetHandle uintptr) error
	IpsetTest(ipsetHandle uintptr, entry string) (bool, error)
	PacketFilterStart(firewallName string, receiveCallback, loggingCallback func(uintptr, uintptr) uintptr) error
	PacketFilterClose() error
	PacketFilterForward(info *PacketInfo, packetBytes []byte) error
	AppendFilter(outbound bool, filterName string) error
	InsertFilter(outbound bool, priority int, filterName string) error
	DestroyFilter(filterName string) error
	EmptyFilter(filterName string) error
	GetFilterList(outbound bool) ([]string, error)
	AppendFilterCriteria(filterName, criteriaName string, ruleSpec *RuleSpec, ipsetRuleSpecs []IpsetRuleSpec) error
	DeleteFilterCriteria(filterName, criteriaName string) error
	GetCriteriaList(format int) (string, error)
}

type wrapper struct {
	driverHandle uintptr
}

// Wrapper is the driver/dll wrapper implementation
var Wrapper = WrapDriver(&wrapper{})

func (w *wrapper) initDriverHandle() {
	if w.driverHandle == 0 || syscall.Handle(w.driverHandle) == syscall.InvalidHandle {
		if ret, err := Driver.FrontmanOpenShared(); err == nil {
			w.driverHandle = ret
		}
	}
}

func (w *wrapper) GetDestInfo(socket uintptr, destInfo *DestInfo) error {
	w.initDriverHandle()
	if ret, err := Driver.GetDestInfo(w.driverHandle, socket, uintptr(unsafe.Pointer(destInfo))); ret == 0 {
		return fmt.Errorf("GetDestInfo failed: %v", err)
	}
	return nil
}

func (w *wrapper) ApplyDestHandle(socket, destHandle uintptr) error {
	w.initDriverHandle()
	if ret, err := Driver.ApplyDestHandle(socket, destHandle); ret == 0 {
		return fmt.Errorf("ApplyDestHandle failed: %v", err)
	}
	return nil
}

func (w *wrapper) FreeDestHandle(destHandle uintptr) error {
	w.initDriverHandle()
	if ret, err := Driver.FreeDestHandle(destHandle); ret == 0 {
		return fmt.Errorf("FreeDestHandle failed: %v", err)
	}
	return nil
}

func (w *wrapper) NewIpset(name, ipsetType string) (uintptr, error) {
	w.initDriverHandle()
	var ipsetHandle uintptr
	if ret, err := Driver.NewIpset(w.driverHandle, marshalString(name), marshalString(ipsetType), uintptr(unsafe.Pointer(&ipsetHandle))); ret == 0 {
		return 0, fmt.Errorf("NewIpset failed: %v", err)
	}
	return ipsetHandle, nil
}

func (w *wrapper) GetIpset(name string) (uintptr, error) {
	w.initDriverHandle()
	var ipsetHandle uintptr
	if ret, err := Driver.GetIpset(w.driverHandle, marshalString(name), uintptr(unsafe.Pointer(&ipsetHandle))); ret == 0 {
		return 0, fmt.Errorf("GetIpset failed: %v", err)
	}
	return ipsetHandle, nil
}

func (w *wrapper) DestroyAllIpsets(prefix string) error {
	w.initDriverHandle()
	if ret, err := Driver.DestroyAllIpsets(w.driverHandle, marshalString(prefix)); ret == 0 {
		return fmt.Errorf("DestroyAllIpsets failed: %v", err)
	}
	return nil
}

func (w *wrapper) ListIpsets() ([]string, error) {
	w.initDriverHandle()
	// first query for needed buffer size
	var bytesNeeded, ignore uint32
	ret, err := Driver.ListIpsets(w.driverHandle, 0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if ret != 0 && bytesNeeded == 0 {
		return []string{}, nil
	}
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("ListIpsets failed: %v", err)
	}
	if bytesNeeded%2 != 0 {
		return nil, fmt.Errorf("ListIpsets failed: odd result (%d)", bytesNeeded)
	}
	// then allocate buffer for wide string and call again
	buf := make([]uint16, bytesNeeded/2)
	ret, err = Driver.ListIpsets(w.driverHandle, uintptr(unsafe.Pointer(&buf[0])), uintptr(bytesNeeded), uintptr(unsafe.Pointer(&ignore)))
	if ret == 0 {
		return nil, fmt.Errorf("ListIpsets failed: %v", err)
	}
	str := syscall.UTF16ToString(buf)
	return strings.Split(str, ","), nil
}

func (w *wrapper) ListIpsetsDetail(format int) (string, error) {
	w.initDriverHandle()
	// first query for needed buffer size
	var bytesNeeded, ignore uint32
	emptyStr := ""
	ret, err := Driver.ListIpsetsDetail(w.driverHandle, uintptr(format), 0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if ret != 0 && bytesNeeded == 0 {
		return emptyStr, nil
	}
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return emptyStr, fmt.Errorf("ListIpsetsDetail failed: %v", err)
	}
	if bytesNeeded%2 != 0 {
		return emptyStr, fmt.Errorf("ListIpsetsDetail failed: odd result (%d)", bytesNeeded)
	}
	// then allocate buffer for wide string and call again
	buf := make([]uint16, bytesNeeded/2)
	ret, err = Driver.ListIpsetsDetail(w.driverHandle, uintptr(format), uintptr(unsafe.Pointer(&buf[0])), uintptr(bytesNeeded), uintptr(unsafe.Pointer(&ignore)))
	if ret == 0 {
		return emptyStr, fmt.Errorf("ListIpsetsDetail failed: %v", err)
	}
	str := syscall.UTF16ToString(buf)
	return str, nil
}

func (w *wrapper) IpsetAdd(ipsetHandle uintptr, entry string, timeout int) error {
	w.initDriverHandle()
	if ret, err := Driver.IpsetAdd(w.driverHandle, ipsetHandle, marshalString(entry), uintptr(timeout)); ret == 0 {
		// no error if already exists
		if err == windows.ERROR_ALREADY_EXISTS {
			return nil
		}
		return fmt.Errorf("IpsetAdd failed: %v", err)
	}
	return nil
}

func (w *wrapper) IpsetAddOption(ipsetHandle uintptr, entry, option string, timeout int) error {
	w.initDriverHandle()
	if ret, err := Driver.IpsetAddOption(w.driverHandle, ipsetHandle, marshalString(entry), marshalString(option), uintptr(timeout)); ret == 0 {
		return fmt.Errorf("IpsetAddOption failed: %v", err)
	}
	return nil
}

func (w *wrapper) IpsetDelete(ipsetHandle uintptr, entry string) error {
	w.initDriverHandle()
	if ret, err := Driver.IpsetDelete(w.driverHandle, ipsetHandle, marshalString(entry)); ret == 0 {
		return fmt.Errorf("IpsetDelete failed: %v", err)
	}
	return nil
}

func (w *wrapper) IpsetDestroy(ipsetHandle uintptr) error {
	w.initDriverHandle()
	if ret, err := Driver.IpsetDestroy(w.driverHandle, ipsetHandle); ret == 0 {
		return fmt.Errorf("IpsetDestroy failed: %v", err)
	}
	return nil
}

func (w *wrapper) IpsetFlush(ipsetHandle uintptr) error {
	w.initDriverHandle()
	if ret, err := Driver.IpsetFlush(w.driverHandle, ipsetHandle); ret == 0 {
		return fmt.Errorf("IpsetFlush failed: %v", err)
	}
	return nil
}

func (w *wrapper) IpsetTest(ipsetHandle uintptr, entry string) (bool, error) {
	w.initDriverHandle()
	if ret, err := Driver.IpsetTest(w.driverHandle, ipsetHandle, marshalString(entry)); ret == 0 {
		if err == nil {
			return false, nil
		}
		return false, fmt.Errorf("IpsetTest failed: %v", err)
	}
	return true, nil
}

func (w *wrapper) PacketFilterStart(firewallName string, receiveCallback, loggingCallback func(uintptr, uintptr) uintptr) error {
	w.initDriverHandle()
	if ret, err := Driver.PacketFilterStart(w.driverHandle, marshalString(firewallName), syscall.NewCallbackCDecl(receiveCallback), syscall.NewCallbackCDecl(loggingCallback)); ret == 0 {
		return fmt.Errorf("PacketFilterStart failed: %v", err)
	}
	return nil
}

func (w *wrapper) PacketFilterClose() error {
	w.initDriverHandle()
	if ret, err := Driver.PacketFilterClose(); ret == 0 {
		return fmt.Errorf("PacketFilterClose failed: %v", err)
	}
	return nil
}

func (w *wrapper) PacketFilterForward(info *PacketInfo, packetBytes []byte) error {
	w.initDriverHandle()
	if ret, err := Driver.PacketFilterForward(uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&packetBytes[0]))); ret == 0 {
		return fmt.Errorf("PacketFilterForward failed: %v", err)
	}
	return nil
}

func (w *wrapper) AppendFilter(outbound bool, filterName string) error {
	w.initDriverHandle()
	if ret, err := Driver.AppendFilter(w.driverHandle, marshalBool(outbound), marshalString(filterName)); ret == 0 {
		// no error if already exists
		if err == windows.ERROR_ALREADY_EXISTS {
			return nil
		}
		return fmt.Errorf("AppendFilter failed: %v", err)
	}
	return nil
}

func (w *wrapper) InsertFilter(outbound bool, priority int, filterName string) error {
	w.initDriverHandle()
	if ret, err := Driver.InsertFilter(w.driverHandle, marshalBool(outbound), uintptr(priority), marshalString(filterName)); ret == 0 {
		return fmt.Errorf("InsertFilter failed: %v", err)
	}
	return nil
}

func (w *wrapper) DestroyFilter(filterName string) error {
	w.initDriverHandle()
	if ret, err := Driver.DestroyFilter(w.driverHandle, marshalString(filterName)); ret == 0 {
		return fmt.Errorf("DestroyFilter failed: %v", err)
	}
	return nil
}

func (w *wrapper) EmptyFilter(filterName string) error {
	w.initDriverHandle()
	if ret, err := Driver.EmptyFilter(w.driverHandle, marshalString(filterName)); ret == 0 {
		return fmt.Errorf("EmptyFilter failed: %v", err)
	}
	return nil
}

func (w *wrapper) GetFilterList(outbound bool) ([]string, error) {
	w.initDriverHandle()
	// first query for needed buffer size
	var bytesNeeded, ignore uint32
	ret, err := Driver.GetFilterList(w.driverHandle, marshalBool(outbound), 0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if ret != 0 && bytesNeeded == 0 {
		return []string{}, nil
	}
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("GetFilterList failed: %v", err)
	}
	if bytesNeeded%2 != 0 {
		return nil, fmt.Errorf("GetFilterList failed: odd result (%d)", bytesNeeded)
	}
	// then allocate buffer for wide string and call again
	buf := make([]uint16, bytesNeeded/2)
	ret, err = Driver.GetFilterList(w.driverHandle, marshalBool(outbound), uintptr(unsafe.Pointer(&buf[0])), uintptr(bytesNeeded), uintptr(unsafe.Pointer(&ignore)))
	if ret == 0 {
		return nil, fmt.Errorf("GetFilterList failed: %v", err)
	}
	str := syscall.UTF16ToString(buf)
	return strings.Split(str, ","), nil
}

func (w *wrapper) AppendFilterCriteria(filterName, criteriaName string, ruleSpec *RuleSpec, ipsetRuleSpecs []IpsetRuleSpec) error {
	w.initDriverHandle()
	if len(ipsetRuleSpecs) > 0 {
		if ret, err := Driver.AppendFilterCriteria(w.driverHandle,
			marshalString(filterName),
			marshalString(criteriaName),
			uintptr(unsafe.Pointer(ruleSpec)),
			uintptr(unsafe.Pointer(&ipsetRuleSpecs[0])),
			uintptr(len(ipsetRuleSpecs))); ret == 0 {
			return fmt.Errorf("AppendFilterCriteria failed: %v", err)
		}
	} else {
		if ret, err := Driver.AppendFilterCriteria(w.driverHandle,
			marshalString(filterName),
			marshalString(criteriaName),
			uintptr(unsafe.Pointer(ruleSpec)), 0, 0); ret == 0 {
			return fmt.Errorf("AppendFilterCriteria failed: %v", err)
		}
	}
	return nil
}

func (w *wrapper) DeleteFilterCriteria(filterName, criteriaName string) error {
	w.initDriverHandle()
	if ret, err := Driver.DeleteFilterCriteria(w.driverHandle, marshalString(filterName), marshalString(criteriaName)); ret == 0 {
		return fmt.Errorf("DeleteFilterCriteria failed - could not delete %s: %v", criteriaName, err)
	}
	return nil
}

func (w *wrapper) GetCriteriaList(format int) (string, error) {
	w.initDriverHandle()
	// first query for needed buffer size
	var bytesNeeded, ignore uint32
	emptyStr := ""
	ret, err := Driver.GetCriteriaList(w.driverHandle, uintptr(format), 0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if ret != 0 && bytesNeeded == 0 {
		return emptyStr, nil
	}
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return emptyStr, fmt.Errorf("GetCriteriaList failed: %v", err)
	}
	if bytesNeeded%2 != 0 {
		return emptyStr, fmt.Errorf("GetCriteriaList failed: odd result (%d)", bytesNeeded)
	}
	// then allocate buffer for wide string and call again
	buf := make([]uint16, bytesNeeded/2)
	ret, err = Driver.GetCriteriaList(w.driverHandle, uintptr(format), uintptr(unsafe.Pointer(&buf[0])), uintptr(bytesNeeded), uintptr(unsafe.Pointer(&ignore)))
	if ret == 0 {
		return emptyStr, fmt.Errorf("GetCriteriaList failed: %v", err)
	}
	str := syscall.UTF16ToString(buf)
	return str, nil
}

func marshalString(str string) uintptr {
	return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(str))) //nolint
}

func marshalBool(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
