// +build windows

package protomux

import (
	"fmt"
	"net"
	"strconv"
	"syscall"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.uber.org/zap"
)

var (
	driverDll        = syscall.NewLazyDLL("Frontman.dll")
	proxyStartProc   = driverDll.NewProc("FrontmanProxyStart")
	proxyStopProc    = driverDll.NewProc("FrontmanProxyStop")
	frontManOpenProc = driverDll.NewProc("FrontmanOpenShared")
)

func getDriverHandle() (uintptr, error) {
	driverHandle, _, err := frontManOpenProc.Call()
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return 0, fmt.Errorf("got INVALID_HANDLE_VALUE: %v", err)
	}
	return driverHandle, nil
}

func (m *MultiplexedListener) serve(conn net.Conn) {
	defer m.wg.Done()

	c, ok := conn.(*markedconn.ProxiedConnection)
	if !ok {
		zap.L().Error("Wrong connection type")
		return
	}

	//ip, port := c.GetOriginalDestination()
	remoteAddr := c.RemoteAddr()
	if remoteAddr == nil {
		zap.L().Error("Connection remote address cannot be found. Abort")
		return
	}

	local := false
	if _, ok = m.localIPs[networkOfAddress(remoteAddr.String())]; ok {
		local = true
	}

	var listenerType common.ListenerType
	if local {
		listenerType = common.TCPNetwork
	} else {
		listenerType = common.TCPApplication
	}

	m.RLock()
	target, ok := m.protomap[listenerType]
	m.RUnlock()
	if !ok {
		c.Close() // nolint
		return
	}

	select {
	case target.connection <- c:
	case <-m.done:
		c.Close() // nolint
	}
}

// onStartListening tells Windows proxy driver to start forwarding traffic
func (m *MultiplexedListener) onStartListening() error {
	_, portStr, err := net.SplitHostPort(m.root.Addr().String())
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	driverHandle, err := getDriverHandle()
	if err != nil {
		return err
	}
	dllRet, _, errDll := proxyStartProc.Call(driverHandle, uintptr(port), 0)
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d, err=%v)", proxyStartProc.Name, dllRet, errDll)
	}

	zap.L().Debug(fmt.Sprintf("Windows proxy driver started, forwarding to port %d", port))
	return nil
}

// onStopListening tells Windows proxy driver to stop forwarding traffic
func (m *MultiplexedListener) onStopListening() error {
	driverHandle, err := getDriverHandle()
	if err != nil {
		return err
	}
	dllRet, _, errDll := proxyStopProc.Call(driverHandle)
	if dllRet == 0 {
		return fmt.Errorf("%s failed (ret=%d, err=%v)", proxyStopProc.Name, dllRet, errDll)
	}

	zap.L().Debug("Windows proxy driver stopped")
	return nil
}
