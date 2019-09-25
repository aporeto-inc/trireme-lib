// +build windows

package markedconn

import (
	"fmt"
	"net"
	"syscall"

	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	"go.uber.org/zap"
)

func makeDialer(mark int, nativeData *NativeData) net.Dialer {
	// nativeData is the destHandle
	return net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// call FrontmanApplyDestHandle to update WFP redirect data before the connect() call on the new socket
				dllRet, _, err := frontman.ApplyDestHandleProc.Call(fd, nativeData.handle)
				if dllRet == 0 {
					zap.L().Error(fmt.Sprintf("%s failed: %v", frontman.ApplyDestHandleProc.Name, err))
				}
			})
		},
	}
}

func makeListenerConfig(mark int) net.ListenConfig {
	return net.ListenConfig{}
}
