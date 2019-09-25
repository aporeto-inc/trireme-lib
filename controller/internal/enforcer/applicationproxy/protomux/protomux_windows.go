// +build windows

package protomux

import (
	"net"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.uber.org/zap"
)

func (m *MultiplexedListener) serve(conn net.Conn) {
	defer m.wg.Done()

	c, ok := conn.(*markedconn.ProxiedConnection)
	if !ok {
		zap.L().Error("Wrong connection type")
		return
	}

	ip, port := c.GetOriginalDestination()
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
		_, serviceData, err := m.registry.RetrieveServiceDataByIDAndNetwork(m.puID, ip, port, "")
		if err != nil {
			zap.L().Error("Cannot discover target service",
				zap.String("ContextID", m.puID),
				zap.String("ip", ip.String()),
				zap.Int("port", port),
				zap.Error(err),
			)
			return
		}
		listenerType = serviceData.ServiceType
	} else {
		pctx, err := m.registry.RetrieveExposedServiceContext(ip, port, "")
		if err != nil {
			zap.L().Error("Cannot discover target service", zap.String("ip", ip.String()), zap.Int("port", port))
			return
		}

		listenerType = pctx.Type
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
