// +build windows

package provider

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"

	"github.com/aporeto-inc/go-ipset/ipset"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
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

type winIPSet struct {
	handle uintptr
	name   string // for debugging
}

// NewIpset returns an IpsetProvider interface based on the go-ipset
// external package.
func (i *ipsetProvider) NewIpset(name string, ipsetType string, p *ipset.Params) (Ipset, error) {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to get driver handle: %v", err)
	}
	var ipsetHandle uintptr
	dllRet, _, err := frontman.NewIpsetProc.Call(driverHandle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))), //nolint:staticcheck
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ipsetType))), uintptr(unsafe.Pointer(&ipsetHandle))) //nolint:staticcheck
	if dllRet == 0 {
		return nil, fmt.Errorf("%s failed (ret=%d err=%v)", frontman.NewIpsetProc.Name, dllRet, err)
	}
	return &winIPSet{ipsetHandle, name}, nil
}

// GetIpset gets the ipset object from the name.
// Note that the interface can't return error here, but since it's possible to fail in Windows,
// we log error and return incomplete object, and expect a failure from Frontman on a later call.
func (i *ipsetProvider) GetIpset(name string) Ipset {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		zap.L().Error("failed to get driver handle", zap.Error(err))
		return &winIPSet{0, name}
	}
	var ipsetHandle uintptr
	dllRet, _, err := frontman.GetIpsetProc.Call(driverHandle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))), //nolint:staticcheck
		uintptr(unsafe.Pointer(&ipsetHandle)))
	if dllRet == 0 {
		zap.L().Error(fmt.Sprintf("%s failed (ret=%d err=%v)", frontman.GetIpsetProc.Name, dllRet, err), zap.Error(err))
		return &winIPSet{0, name}
	}
	return &winIPSet{ipsetHandle, name}
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *ipsetProvider) DestroyAll(prefix string) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	dllRet, _, err := frontman.DestroyAllIpsetsProc.Call(driverHandle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(prefix)))) //nolint:staticcheck
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", frontman.DestroyAllIpsetsProc.Name, dllRet, err)
	}
	return nil
}

func (i *ipsetProvider) ListIPSets() ([]string, error) {
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

// NewGoIPsetProvider Return a Go IPSet Provider
func NewGoIPsetProvider() IpsetProvider {
	return &ipsetProvider{}
}

func (w *winIPSet) Add(entry string, timeout int) error {
	zap.L().Debug(fmt.Sprintf("add ipset entry %s to %s", entry, w.name))
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	dllRet, _, err := frontman.IpsetAddProc.Call(driverHandle, w.handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))), uintptr(timeout)) //nolint:staticcheck
	if dllRet == 0 {
		// no error if already exists
		if err == windows.ERROR_ALREADY_EXISTS {
			return nil
		}
		return fmt.Errorf("%s failed (ret=%d err=%v)", frontman.IpsetAddProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIPSet) AddOption(entry string, option string, timeout int) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	dllRet, _, err := frontman.IpsetAddOptionProc.Call(driverHandle, w.handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))),                    //nolint:staticcheck
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(option))), uintptr(timeout)) //nolint:staticcheck
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", frontman.IpsetAddOptionProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIPSet) Del(entry string) error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	dllRet, _, err := frontman.IpsetDeleteProc.Call(driverHandle, w.handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry)))) //nolint:staticcheck
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", frontman.IpsetDeleteProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIPSet) Destroy() error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	dllRet, _, err := frontman.IpsetDestroyProc.Call(driverHandle, w.handle)
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", frontman.IpsetDestroyProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIPSet) Flush() error {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	dllRet, _, err := frontman.IpsetFlushProc.Call(driverHandle, w.handle)
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d err=%v)", frontman.IpsetFlushProc.Name, dllRet, err)
	}
	return nil
}

func (w *winIPSet) Test(entry string) (bool, error) {
	driverHandle, err := frontman.GetDriverHandle()
	if err != nil {
		return false, fmt.Errorf("failed to get driver handle: %v", err)
	}
	dllRet, _, err := frontman.IpsetTestProc.Call(driverHandle, w.handle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry)))) //nolint:staticcheck
	if dllRet == 0 {
		return false, fmt.Errorf("%s failed (ret=%d err=%v)", frontman.IpsetTestProc.Name, dllRet, err)
	}
	return true, nil
}
