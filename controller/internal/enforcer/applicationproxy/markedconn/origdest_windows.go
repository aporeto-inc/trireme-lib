// +build windows

package markedconn

import (
	"fmt"
	"net"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.uber.org/zap"
)

func getOriginalDestPlatform(rawConn passFD, v4Proto bool) (net.IP, int, *PlatformData, error) {
	var netIP net.IP
	var port int
	var destHandle uintptr
	var err error

	driverHandle, errDll := frontman.GetDriverHandle()
	if errDll != nil {
		return nil, 0, nil, fmt.Errorf("failed to get driver handle: %v", errDll)
	}

	freeFunc := func(fd uintptr) {
		dllRet, _, errDll := frontman.FreeDestHandleProc.Call(fd)
		if dllRet == 0 {
			zap.L().Error(fmt.Sprintf("%s failed: %v", frontman.FreeDestHandleProc.Name, errDll))
		}
	}

	ctrlFunc := func(fd uintptr) {
		var destInfo frontman.DestInfo
		dllRet, _, errDll := frontman.GetDestInfoProc.Call(driverHandle, fd, uintptr(unsafe.Pointer(&destInfo)))
		if dllRet == 0 {
			err = fmt.Errorf("%s failed (ret=%d, err=%v)", frontman.GetDestInfoProc.Name, dllRet, errDll)
		} else {
			destHandle = destInfo.DestHandle
			port = int(destInfo.Port)
			// convert allocated wchar_t* to golang string
			ipAddrStr := frontman.WideCharPointerToString(destInfo.IpAddr)
			netIP = net.ParseIP(ipAddrStr)
			if netIP == nil {
				err = fmt.Errorf("%s failed to get valid IP (%s)", frontman.GetDestInfoProc.Name, ipAddrStr)
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
