// +build !linux

package tcp

import "net"

// CompleteEndPointAuthorization -- Aporeto Handshake on top of a completed connection
// We will define states here equivalent to SYN_SENT AND SYN_RECEIVED
func (p *Proxy) CompleteEndPointAuthorization(downIP net.IP, downPort int, upConn, downConn net.Conn) (bool, error) {

	// If the backend is not a local IP it means that we are a client.
	if p.isLocal(upConn) {
		return p.StartClientAuthStateMachine(downIP, downPort, downConn)
	}

	isEncrypted, err := p.StartServerAuthStateMachine(downIP, downPort, upConn)
	if err != nil {
		return false, err
	}

	return isEncrypted, nil
}
