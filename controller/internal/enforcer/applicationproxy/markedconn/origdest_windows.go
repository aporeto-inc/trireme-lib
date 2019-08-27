// +build windows

package markedconn

import (
	"fmt"
	"net"
	"unsafe"

	"go.uber.org/zap"
)

type frontmanDestInfo struct {
	ipAddr     *uint16 // WCHAR* IPAddress		Destination address allocated and will be free by FrontmanFreeDestHandle
	port       uint16  // USHORT Port			Destination port
	outbound   int32   // INT32 Outbound		Whether or not this is an outbound or inbound connection
	processId  uint64  // UINT64 ProcessId		Process id.  Only available for outbound connections
	destHandle uintptr // LPVOID DestHandle		Handle to memory that must be freed by called ProxyDestConnected when connection is established.
}

func getOriginalDestPlatform(rawConn passFD, v4Proto bool) (net.IP, int, *NativeData, error) {
	var netIP net.IP
	var port int
	var destHandle uintptr
	var err error

	driverHandle, errDll := getDriverHandle()
	if errDll != nil {
		return nil, 0, nil, fmt.Errorf("failed to get driver handle: %v", errDll)
	}

	freeFunc := func(fd uintptr) {
		dllRet, _, errDll := freeDestHandleProc.Call(fd)
		if dllRet == 0 {
			zap.L().Error(fmt.Sprintf("%s failed: %v", freeDestHandleProc.Name, errDll))
		}
	}

	ctrlFunc := func(fd uintptr) {
		var destInfo frontmanDestInfo
		dllRet, _, errDll := getDestInfoProc.Call(driverHandle, fd, uintptr(unsafe.Pointer(&destInfo)))
		if dllRet == 0 {
			err = fmt.Errorf("%s failed (ret=%d, err=%v)", getDestInfoProc.Name, dllRet, errDll)
		} else {
			destHandle = destInfo.destHandle
			port = int(destInfo.port)
			// convert allocated wchar_t* to golang string
			ipAddrStr := WideCharPointerToString(destInfo.ipAddr)
			netIP = net.ParseIP(ipAddrStr)
			if netIP == nil {
				err = fmt.Errorf("%s failed to get valid IP (%S)", getDestInfoProc.Name, ipAddrStr)
				// FrontmanGetDestInfo returned success, so clean up acquired native resources
				freeFunc(fd)
			}
		}
	}

	if err1 := rawConn.Control(ctrlFunc); err1 != nil {
		return nil, 0, nil, fmt.Errorf("Failed to get original destination: %s", err)
	}

	if err != nil {
		return nil, 0, nil, err
	}

	return netIP, port, &NativeData{destHandle, freeFunc}, nil
}
