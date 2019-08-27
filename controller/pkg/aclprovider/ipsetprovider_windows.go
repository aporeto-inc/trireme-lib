// +build windows

package provider

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aporeto-inc/go-ipset/ipset"
)

// IpsetProvider returns a fabric for Ipset.
type IpsetProvider interface {
	NewIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error)
	GetIpset(name string) Ipset
	DestroyAll(prefix string) error
	ListIPSets() ([]string, error)
}

// Ipset is an abstraction of all the methods an implementation of userspace
// ipsets need to provide.
type Ipset interface {
	Add(entry string, timeout int) error
	AddOption(entry string, option string, timeout int) error
	Del(entry string) error
	Destroy() error
	Flush() error
	Test(entry string) (bool, error)
}

type ipsetProvider struct{}

type winIpSet struct {
	handle  uintptr
	dllType int
}

var (
	driverDll        = syscall.NewLazyDLL("Frontman.dll")
	newIpSetProc     = driverDll.NewProc("IpsetProvider_NewIpset")
	getIpSetProc     = driverDll.NewProc("IpsetProvider_GetIpset")
	destroyAllProc   = driverDll.NewProc("IpsetProvider_DestroyAll")
	listIpSetsProc   = driverDll.NewProc("IpsetProvider_ListIPSets")
	addProc          = driverDll.NewProc("Ipset_Add")
	addOptionProc    = driverDll.NewProc("Ipset_AddOption")
	deleteProc       = driverDll.NewProc("Ipset_Delete")
	destroyProc      = driverDll.NewProc("Ipset_Destroy")
	flushProc        = driverDll.NewProc("Ipset_Flush")
	testProc         = driverDll.NewProc("Ipset_Test")
	frontManOpenProc = driverDll.NewProc("FrontmanOpenShared")
)

const (
	IpsetProviderTypeExclusions = 1
)

const (
	IpsetErrorInsufficientBuffer = uint32(0x55550004)
)

func getTypeForDll(name string) int {
	if name == "TRI-v4-Excluded" || name == "TRI-v6-Excluded" {
		return IpsetProviderTypeExclusions
	}
	return 0
}

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *ipsetProvider) NewIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error) {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to get driver handle: %v", err)
	}
	typeForDll := getTypeForDll(name)
	// TODO(windows): for now don't pass on to the driver if it's not excluded type
	if typeForDll != IpsetProviderTypeExclusions {
		return &winIpSet{}, nil
	}
	var ipsetHandle uintptr
	dllRet, _, err := newIpSetProc.Call(driverHandle, uintptr(typeForDll), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ipsetType))), uintptr(unsafe.Pointer(&ipsetHandle)))
	if dllRet == 0 {
		return nil, fmt.Errorf("%s failed (ret=%d err=%v)", newIpSetProc.Name, dllRet, err)
	}
	return &winIpSet{ipsetHandle, typeForDll}, nil
}

// GetIpset gets the ipset object from the name.
// TODO(windows): should this return error?
func (i *ipsetProvider) GetIpset(name string) Ipset {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return nil //, fmt.Errorf("failed to get driver handle: %v", err)
	}
	typeForDll := getTypeForDll(name)
	var ipsetHandle uintptr
	dllRet, _, _ := getIpSetProc.Call(driverHandle, uintptr(typeForDll), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
		uintptr(unsafe.Pointer(&ipsetHandle)))
	if dllRet == 0 {
		return &winIpSet{} //, fmt.Errorf("%s failed (ret=%d err=%v)", getIpSetProc.Name, dllRet, err)
	}
	return &winIpSet{ipsetHandle, typeForDll} //, nil
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *ipsetProvider) DestroyAll(prefix string) error {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	// TODO(windows): hardcode exclusion type until we have more types
	dllRet, _, err := destroyAllProc.Call(driverHandle, IpsetProviderTypeExclusions, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(prefix))))
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", destroyAllProc.Name, dllRet, err)
	}
	return nil
}

func (i *ipsetProvider) ListIPSets() ([]string, error) {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to get driver handle: %v", err)
	}
	// first query for needed buffer size
	var bytesNeeded, ignore uint32
	_, _, err = listIpSetsProc.Call(driverHandle, IpsetProviderTypeExclusions, 0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if err == syscall.Errno(0) && bytesNeeded == 0 {
		return []string{}, nil
	}
	if err != syscall.Errno(IpsetErrorInsufficientBuffer) {
		return nil, fmt.Errorf("%s failed: %v", listIpSetsProc.Name, err)
	}
	if bytesNeeded%2 != 0 {
		return nil, fmt.Errorf("%s failed: odd result (%d)", listIpSetsProc.Name, bytesNeeded)
	}
	// then allocate buffer for wide string and call again
	buf := make([]uint16, bytesNeeded/2)
	dllRet, _, err := listIpSetsProc.Call(driverHandle, IpsetProviderTypeExclusions, uintptr(unsafe.Pointer(&buf[0])), uintptr(bytesNeeded), uintptr(unsafe.Pointer(&ignore)))
	if dllRet == 0 {
		return nil, fmt.Errorf("%s failed (ret=%d err=%v)", listIpSetsProc.Name, dllRet, err)
	}
	str := syscall.UTF16ToString(buf)
	ipsets := strings.Split(str, ",")
	return ipsets, nil
}

// NewGoIPsetProvider Return a Go IPSet Provider
func NewGoIPsetProvider() IpsetProvider {
	return &ipsetProvider{}
}

func (w *winIpSet) Add(entry string, timeout int) error {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if w.dllType == 0 {
		// type not handled by driver
		return nil
	}
	dllRet, _, err := addProc.Call(driverHandle, uintptr(w.dllType), w.handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))), uintptr(timeout))
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", addProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) AddOption(entry string, option string, timeout int) error {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if w.dllType == 0 {
		// type not handled by driver
		return nil
	}
	dllRet, _, err := addOptionProc.Call(driverHandle, uintptr(w.dllType), w.handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(option))), uintptr(timeout))
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", addOptionProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) Del(entry string) error {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if w.dllType == 0 {
		// type not handled by driver
		return nil
	}
	dllRet, _, err := deleteProc.Call(driverHandle, uintptr(w.dllType), w.handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))))
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", deleteProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) Destroy() error {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if w.dllType == 0 {
		// type not handled by driver
		return nil
	}
	dllRet, _, err := destroyProc.Call(driverHandle, uintptr(w.dllType), w.handle)
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", destroyProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) Flush() error {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if w.dllType == 0 {
		// type not handled by driver
		return nil
	}
	dllRet, _, err := flushProc.Call(driverHandle, uintptr(w.dllType), w.handle)
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", flushProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) Test(entry string) (bool, error) {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return false, fmt.Errorf("failed to get driver handle: %v", err)
	}
	if w.dllType == 0 {
		// type not handled by driver
		return false, nil
	}
	dllRet, _, err := testProc.Call(driverHandle, uintptr(w.dllType), w.handle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))))
	if dllRet == 0 {
		return false, fmt.Errorf("%s failed (ret=%d err=%v)", testProc.Name, dllRet, err)
	}
	return true, nil
}

func getDriverHandle() (uintptr, error) {
	driverHandle, _, err := frontManOpenProc.Call()
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return 0, fmt.Errorf("got INVALID_HANDLE_VALUE: %v", err)
	}
	return driverHandle, nil
}
