// +build windows

package markedconn

import (
	"net"
	"syscall"

	"go.aporeto.io/trireme-lib/v11/controller/internal/windows/frontman"
	"go.uber.org/zap"
)

func makeDialer(mark int, platformData *PlatformData) net.Dialer {
	// platformData is the destHandle
	return net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// call FrontmanApplyDestHandle to update WFP redirect data before the connect() call on the new socket
				if err := frontman.Wrapper.ApplyDestHandle(fd, platformData.handle); err != nil {
					zap.L().Error("could not update proxy redirect", zap.Error(err))
				}
			})
		},
	}
}

func makeListenerConfig(mark int) net.ListenConfig {
	return net.ListenConfig{}
}
