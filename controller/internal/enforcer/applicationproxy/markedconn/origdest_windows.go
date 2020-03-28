// +build windows

package markedconn

import (
	"fmt"
	"net"

	"go.aporeto.io/trireme-lib/controller/internal/windows"
	"go.aporeto.io/trireme-lib/utils/frontman"
	"go.uber.org/zap"
)

func getOriginalDestPlatform(rawConn passFD, v4Proto bool) (net.IP, int, *PlatformData, error) {
	var netIP net.IP
	var port int
	var destHandle uintptr
	var err error

	freeFunc := func(fd uintptr) {
		if err1 := frontman.Wrapper.FreeDestHandle(fd); err1 != nil {
			zap.L().Error("failed to free dest handle", zap.Error(err1))
		}
	}

	ctrlFunc := func(fd uintptr) {
		var destInfo frontman.DestInfo
		if err1 := frontman.Wrapper.GetDestInfo(fd, &destInfo); err1 != nil {
			err = err1
			return
		}
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

	if err1 := rawConn.Control(ctrlFunc); err1 != nil {
		return nil, 0, nil, fmt.Errorf("Failed to get original destination: %s", err)
	}

	if err != nil {
		return nil, 0, nil, err
	}

	return netIP, port, &PlatformData{destHandle, freeFunc}, nil
}
