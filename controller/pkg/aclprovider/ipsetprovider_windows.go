// +build windows

package provider

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.uber.org/zap"
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
	id uint32
}

var (
	driverDll      = syscall.NewLazyDLL("Frontman.dll")
	newIpSetProc   = driverDll.NewProc("IpsetProvider_NewIpset")
	getIpSetProc   = driverDll.NewProc("IpsetProvider_GetIpset")
	destroyAllProc = driverDll.NewProc("IpsetProvider_DestroyAll")
	listIpSetsProc = driverDll.NewProc("IpsetProvider_ListIPSets")
	addProc        = driverDll.NewProc("Ipset_Add")
	addOptionProc  = driverDll.NewProc("Ipset_AddOption")
	deleteProc     = driverDll.NewProc("Ipset_Delete")
	destroyProc    = driverDll.NewProc("Ipset_Destory")
	flushProc      = driverDll.NewProc("Ipset_Flush")
	testProc       = driverDll.NewProc("Ipset_Test")
)

const IpsetInsufficientBuffer = uint32(0x55550004)

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *ipsetProvider) NewIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error) {
	if !isDllEvenHere() {
		return &winIpSet{}, nil
	}
	var ipsetId uint32
	dllRet, _, err := newIpSetProc.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ipsetType))), uintptr(unsafe.Pointer(&ipsetId)))
	if err != syscall.Errno(0) || dllRet == 0 {
		return nil, fmt.Errorf("%s failed (ret=%d err=%v)", newIpSetProc.Name, dllRet, err)
	}
	return &winIpSet{ipsetId}, nil
}

// GetIpset gets the ipset object from the name.
// TODO(windows): should this return error?
func (i *ipsetProvider) GetIpset(name string) Ipset {
	if !isDllEvenHere() {
		return &winIpSet{}
	}
	var ipsetId uint32
	dllRet, _, err := getIpSetProc.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
		uintptr(unsafe.Pointer(&ipsetId)))
	if err != syscall.Errno(0) || dllRet == 0 {
		return &winIpSet{} //, fmt.Errorf("%s failed (ret=%d err=%v)", getIpSetProc.Name, dllRet, err)
	}
	return &winIpSet{ipsetId} //, nil
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *ipsetProvider) DestroyAll(prefix string) error {
	if !isDllEvenHere() {
		return nil
	}
	dllRet, _, err := destroyAllProc.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(prefix))))
	if err != syscall.Errno(0) || dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", destroyAllProc.Name, dllRet, err)
	}
	return nil
}

func (i *ipsetProvider) ListIPSets() ([]string, error) {
	if !isDllEvenHere() {
		return []string{}, nil
	}
	// first query for needed buffer size
	var bytesNeeded, ignore uint32
	_, _, err := listIpSetsProc.Call(0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if err != syscall.Errno(IpsetInsufficientBuffer) {
		return nil, fmt.Errorf("%s failed: %v", listIpSetsProc.Name, err)
	}
	if bytesNeeded == 0 {
		return []string{}, nil
	}
	if bytesNeeded%2 != 0 {
		return nil, fmt.Errorf("%s failed: odd result (%d)", listIpSetsProc.Name, bytesNeeded)
	}
	// then allocate buffer for wide string and call again
	buf := make([]uint16, bytesNeeded/2)
	dllRet, _, err := listIpSetsProc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(bytesNeeded), uintptr(unsafe.Pointer(&ignore)))
	if err != syscall.Errno(0) || dllRet == 0 {
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
	if !isDllEvenHere() {
		return nil
	}
	dllRet, _, err := addProc.Call(uintptr(w.id), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))),
		uintptr(timeout))
	if err != syscall.Errno(0) || dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", addProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) AddOption(entry string, option string, timeout int) error {
	if !isDllEvenHere() {
		return nil
	}
	dllRet, _, err := addOptionProc.Call(uintptr(w.id), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(option))), uintptr(timeout))
	if err != syscall.Errno(0) || dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", addOptionProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) Del(entry string) error {
	if !isDllEvenHere() {
		return nil
	}
	dllRet, _, err := deleteProc.Call(uintptr(w.id), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))))
	if err != syscall.Errno(0) || dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", deleteProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) Destroy() error {
	if !isDllEvenHere() {
		return nil
	}
	dllRet, _, err := destroyProc.Call(uintptr(w.id))
	if err != syscall.Errno(0) || dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", destroyProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) Flush() error {
	if !isDllEvenHere() {
		return nil
	}
	dllRet, _, err := flushProc.Call(uintptr(w.id))
	if err != syscall.Errno(0) || dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", flushProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIpSet) Test(entry string) (bool, error) {
	if !isDllEvenHere() {
		return false, nil
	}
	dllRet, _, err := testProc.Call(uintptr(w.id), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))))
	if err != syscall.Errno(0) || dllRet == 0 {
		return false, fmt.Errorf("%s failed (ret=%d err=%v)", testProc.Name, dllRet, err)
	}
	return true, nil
}

// TODO(windows): temporary function until driver/dll are integrated
func isDllEvenHere() bool {
	err := driverDll.Load()
	if err != nil {
		zap.L().Error(err.Error())
		return false
	}
	return true
}
