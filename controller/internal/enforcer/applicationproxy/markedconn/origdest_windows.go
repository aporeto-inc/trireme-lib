// +build windows

package markedconn

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/internal/windows"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.uber.org/zap"
)

func getOriginalDestPlatform(rawConn passFD, v4Proto bool) (net.IP, int, *PlatformData, error) {
	var netIP net.IP
	var port int
	var destHandle uintptr
	var err error

	driverHandle, errDll := frontman.Driver.FrontmanOpenShared()
	if errDll != nil {
		return nil, 0, nil, fmt.Errorf("failed to get driver handle: %v", errDll)
	}
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return nil, 0, nil, fmt.Errorf("failed to get driver handle")
	}

	freeFunc := func(fd uintptr) {
		dllRet, errDll := frontman.Driver.FreeDestHandle(fd)
		if dllRet == 0 {
			zap.L().Error(fmt.Sprintf("FreeDestHandle failed: %v", errDll))
		}
	}

	ctrlFunc := func(fd uintptr) {
		var destInfo frontman.DestInfo
		dllRet, errDll := frontman.Driver.GetDestInfo(driverHandle, fd, uintptr(unsafe.Pointer(&destInfo)))
		if dllRet == 0 {
			err = fmt.Errorf("GetDestInfo failed (ret=%d, err=%v)", dllRet, errDll)
		} else {
			destHandle = destInfo.DestHandle
			port = int(destInfo.Port)
			// convert allocated wchar_t* to golang string
			ipAddrStr := windows.WideCharPointerToString(destInfo.IPAddr)
			netIP = net.ParseIP(ipAddrStr)
			if netIP == nil {
				err = fmt.Errorf("GetDestInfo failed to get valid IP (%s)", ipAddrStr)
				// FrontmanGetDestInfo returned success, so clean up acquired resources
				freeFunc(destHandle)
			}
		}
	}

	if err1 := rawConn.Control(ctrlFunc); err1 != nil {
		return nil, 0, nil, fmt.Errorf("Failed to get original destination: %s", err)
	}

	if err != nil {
		return nil, 0, nil, err
	}

	return netIP, port, &PlatformData{destHandle, freeFunc}, nil
}
