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
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		return nil, fmt.Errorf("failed to get driver handle: %v", err)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return nil, fmt.Errorf("failed to get driver handle")
	}
	var ipsetHandle uintptr
	dllRet, err := frontman.Driver.NewIpset(driverHandle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))), //nolint:staticcheck
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ipsetType))), uintptr(unsafe.Pointer(&ipsetHandle))) //nolint:staticcheck
	if dllRet == 0 {
		return nil, fmt.Errorf("NewIpset failed (ret=%d err=%v)", dllRet, err)
	}
	return &winIPSet{ipsetHandle, name}, nil
}

// GetIpset gets the ipset object from the name.
// Note that the interface can't return error here, but since it's possible to fail in Windows,
// we log error and return incomplete object, and expect a failure from Frontman on a later call.
func (i *ipsetProvider) GetIpset(name string) Ipset {
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		zap.L().Error("failed to get driver handle", zap.Error(err))
		return &winIPSet{0, name}
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		zap.L().Error("failed to get driver handle")
		return &winIPSet{0, name}
	}
	var ipsetHandle uintptr
	dllRet, err := frontman.Driver.GetIpset(driverHandle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))), //nolint:staticcheck
		uintptr(unsafe.Pointer(&ipsetHandle)))
	if dllRet == 0 {
		zap.L().Error(fmt.Sprintf("GetIpset failed (ret=%d err=%v)", dllRet, err), zap.Error(err))
		return &winIPSet{0, name}
	}
	return &winIPSet{ipsetHandle, name}
}

// DestroyAll destroys all the ipsets - it will fail if there are existing references
func (i *ipsetProvider) DestroyAll(prefix string) error {
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return fmt.Errorf("failed to get driver handle")
	}
	dllRet, err := frontman.Driver.DestroyAllIpsets(driverHandle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(prefix)))) //nolint:staticcheck
	if dllRet == 0 {
		return fmt.Errorf("DestroyAllIpsets failed (ret=%d err=%v)", dllRet, err)
	}
	return nil
}

func (i *ipsetProvider) ListIPSets() ([]string, error) {
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		return nil, fmt.Errorf("failed to get driver handle: %v", err)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return nil, fmt.Errorf("failed to get driver handle")
	}
	// first query for needed buffer size
	var bytesNeeded, ignore uint32
	dllRet, err := frontman.Driver.ListIpsets(driverHandle, 0, 0, uintptr(unsafe.Pointer(&bytesNeeded)))
	if dllRet != 0 && bytesNeeded == 0 {
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
	dllRet, err = frontman.Driver.ListIpsets(driverHandle, uintptr(unsafe.Pointer(&buf[0])), uintptr(bytesNeeded), uintptr(unsafe.Pointer(&ignore)))
	if dllRet == 0 {
		return nil, fmt.Errorf("ListIpsets failed (ret=%d err=%v)", dllRet, err)
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
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return fmt.Errorf("failed to get driver handle")
	}
	dllRet, err := frontman.Driver.IpsetAdd(driverHandle, w.handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))), uintptr(timeout)) //nolint:staticcheck
	if dllRet == 0 {
		// no error if already exists
		if err == windows.ERROR_ALREADY_EXISTS {
			return nil
		}
		return fmt.Errorf("IpsetAdd failed (ret=%d err=%v)", dllRet, err)
	}
	return nil
}

func (w *winIPSet) AddOption(entry string, option string, timeout int) error {
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return fmt.Errorf("failed to get driver handle")
	}
	dllRet, err := frontman.Driver.IpsetAddOption(driverHandle, w.handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry))),                    //nolint:staticcheck
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(option))), uintptr(timeout)) //nolint:staticcheck
	if dllRet == 0 {
		return fmt.Errorf("IpsetAddOption failed (ret=%d err=%v)", dllRet, err)
	}
	return nil
}

func (w *winIPSet) Del(entry string) error {
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return fmt.Errorf("failed to get driver handle")
	}
	dllRet, err := frontman.Driver.IpsetDelete(driverHandle, w.handle,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry)))) //nolint:staticcheck
	if dllRet == 0 {
		return fmt.Errorf("IpsetDelete failed (ret=%d err=%v)", dllRet, err)
	}
	return nil
}

func (w *winIPSet) Destroy() error {
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return fmt.Errorf("failed to get driver handle")
	}
	dllRet, err := frontman.Driver.IpsetDestroy(driverHandle, w.handle)
	if dllRet == 0 {
		return fmt.Errorf("IpsetDestroy failed (ret=%d err=%v)", dllRet, err)
	}
	return nil
}

func (w *winIPSet) Flush() error {
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		return fmt.Errorf("failed to get driver handle: %v", err)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return fmt.Errorf("failed to get driver handle")
	}
	dllRet, err := frontman.Driver.IpsetFlush(driverHandle, w.handle)
	if dllRet == 0 {
		return fmt.Errorf("IpsetFlush failed (ret=%d err=%v)", dllRet, err)
	}
	return nil
}

func (w *winIPSet) Test(entry string) (bool, error) {
	driverHandle, err := frontman.Driver.FrontmanOpenShared()
	if err != nil {
		return false, fmt.Errorf("failed to get driver handle: %v", err)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return false, fmt.Errorf("failed to get driver handle")
	}
	dllRet, err := frontman.Driver.IpsetTest(driverHandle, w.handle, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(entry)))) //nolint:staticcheck
	if dllRet == 0 {
		return false, fmt.Errorf("IpsetTest failed (ret=%d err=%v)", dllRet, err)
	}
	return true, nil
}
