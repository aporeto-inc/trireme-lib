// +build windows

package markedconn

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"unsafe"

	"github.com/magiconair/properties/assert"
	"go.aporeto.io/trireme-lib/utils/frontman"
)

type abi struct {
	destHandle        uintptr
	destHandleApplied uintptr
	destHandleFreed   uintptr
	destInfoOverride  *frontman.DestInfo
}

var (
	goodIP   = syscall.StringToUTF16("192.168.100.101") //nolint
	badIP    = syscall.StringToUTF16("192.xxxxxxx")     //nolint
	goodPort = uint16(8080)
)

func (a *abi) FrontmanOpenShared() (uintptr, error) {
	return 1234, nil
}

func (a *abi) GetDestInfo(driverHandle, socket, destInfo uintptr) (uintptr, error) {
	destInfoPtr := (*frontman.DestInfo)(unsafe.Pointer(destInfo)) //nolint:govet
	if a.destInfoOverride != nil {
		if a.destInfoOverride.DestHandle == uintptr(syscall.InvalidHandle) {
			return 0, errors.New("INVALID_HANDLE_VALUE")
		}
		*destInfoPtr = *a.destInfoOverride
		return 1, nil
	}
	destInfoPtr.IPAddr = &goodIP[0]
	destInfoPtr.Port = goodPort
	a.destHandle++
	destInfoPtr.DestHandle = a.destHandle
	return 1, nil
}

func (a *abi) ApplyDestHandle(socket, destHandle uintptr) (uintptr, error) {
	if a.destHandleApplied == destHandle {
		return 0, errors.New("ApplyDestHandle called more than once")
	}
	a.destHandleApplied = destHandle
	return 1, nil
}

func (a *abi) FreeDestHandle(destHandle uintptr) (uintptr, error) {
	a.destHandleFreed = destHandle
	return 1, nil
}

func (a *abi) NewIpset(driverHandle, name, ipsetType, ipset uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) GetIpset(driverHandle, name, ipset uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) DestroyAllIpsets(driverHandle, prefix uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) ListIpsets(driverHandle, ipsetNames, ipsetNamesSize, bytesReturned uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) IpsetAdd(driverHandle, ipset, entry, timeout uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) IpsetAddOption(driverHandle, ipset, entry, option, timeout uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) IpsetDelete(driverHandle, ipset, entry uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) IpsetDestroy(driverHandle, ipset uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) IpsetFlush(driverHandle, ipset uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) IpsetTest(driverHandle, ipset, entry uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) PacketFilterStart(frontman, firewallName, receiveCallback, loggingCallback uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) PacketFilterClose() (uintptr, error) {
	return 1, nil
}

func (a *abi) PacketFilterForward(info, packet uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) AppendFilter(driverHandle, outbound, filterName uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) InsertFilter(driverHandle, outbound, priority, filterName uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) DestroyFilter(driverHandle, filterName uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) EmptyFilter(driverHandle, filterName uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) GetFilterList(driverHandle, outbound, buffer, bufferSize, bytesReturned uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) AppendFilterCriteria(driverHandle, filterName, criteriaName, ruleSpec, ipsetRuleSpecs, ipsetRuleSpecCount uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) DeleteFilterCriteria(driverHandle, filterName, criteriaName uintptr) (uintptr, error) {
	return 1, nil
}

type testPassFD struct {
}

func (*testPassFD) Control(f func(uintptr)) error {
	f(0)
	return nil
}

func TestWindowsGetOrigDest(t *testing.T) {

	a := &abi{}
	frontman.Driver = a
	test := &testPassFD{}

	ip, port, pd, _ := getOriginalDestPlatform(test, true)
	assert.Equal(t, ip.String(), syscall.UTF16ToString(goodIP), "ip is wrong")
	assert.Equal(t, port, int(goodPort), "port is wrong")
	pd.postConnectFunc(a.destHandle)
	assert.Equal(t, a.destHandleFreed != 0, true, "destHandle not freed")
}

func TestWindowsGetOrigDestBadDestInfo(t *testing.T) {

	a := &abi{}
	frontman.Driver = a
	test := &testPassFD{}
	a.destInfoOverride = &frontman.DestInfo{DestHandle: uintptr(syscall.InvalidHandle)}

	_, _, _, err := getOriginalDestPlatform(test, true)
	assert.Equal(t, err != nil, true, "GetDestInfo should fail")
	assert.Equal(t, a.destHandleApplied == 0, true, "ApplyDestHandle should not be called")
	assert.Equal(t, a.destHandleFreed == 0, true, "FreeDestHandle should not be called")
}

func TestWindowsGetOrigDestBadIP(t *testing.T) {

	a := &abi{}
	frontman.Driver = a
	test := &testPassFD{}
	a.destHandle = 1000
	a.destInfoOverride = &frontman.DestInfo{IPAddr: &badIP[0], Port: goodPort, DestHandle: a.destHandle}

	_, _, _, err := getOriginalDestPlatform(test, true)
	assert.Equal(t, err != nil, true, "GetDestInfo should fail")
	assert.Equal(t, a.destHandleApplied == 0, true, "ApplyDestHandle should not be called")
	assert.Equal(t, a.destHandleFreed == a.destHandle, true, "FreeDestHandle should be called")
}

func TestSocketListenerWindows(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background()) //nolint
	_, err := NewSocketListener(ctx, ":1111", 100)

	assert.Equal(t, err, nil, "error  should be nil")
	cancel() //nolint
}
