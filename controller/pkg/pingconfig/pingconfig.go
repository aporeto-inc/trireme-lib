package pingconfig

import (
	"sync"
	"time"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
)

// PingConfig holds ping configuration for this connection.
type PingConfig struct {
	socketFd     uintptr
	socketClosed bool
	pingID       string
	iterationID  int
	appListening bool
	seqNum       uint32
	pingReport   *collector.PingReport

	StartTime time.Time

	sync.RWMutex
}

// New returns a new locked access to PingConfig handle.
func New() *PingConfig {
	return &PingConfig{}
}

// SocketFd returns socket file descriptor.
func (p *PingConfig) SocketFd() uintptr {
	p.RLock()
	defer p.RUnlock()

	return p.socketFd
}

// SetSocketFd sets socket file descriptor.
func (p *PingConfig) SetSocketFd(socketFd uintptr) {
	p.Lock()
	defer p.Unlock()

	p.socketFd = socketFd
}

// SocketClosed returns socket closed.
func (p *PingConfig) SocketClosed() bool {
	p.RLock()
	defer p.RUnlock()

	return p.socketClosed
}

// SetSocketClosed sets socket closed.
func (p *PingConfig) SetSocketClosed(socketClosed bool) {
	p.Lock()
	defer p.Unlock()

	p.socketClosed = socketClosed
}

// PingID returns ping ID.
func (p *PingConfig) PingID() string {
	p.RLock()
	defer p.RUnlock()

	return p.pingID
}

// SetPingID sets ping ID.
func (p *PingConfig) SetPingID(pingID string) {
	p.Lock()
	defer p.Unlock()

	p.pingID = pingID
}

// IterationID returns iteration ID.
func (p *PingConfig) IterationID() int {
	p.RLock()
	defer p.RUnlock()

	return p.iterationID
}

// SetIterationID sets iteration ID.
func (p *PingConfig) SetIterationID(iterationID int) {
	p.Lock()
	defer p.Unlock()

	p.iterationID = iterationID
}

// ApplicationListening returns true if an app is listening.
func (p *PingConfig) ApplicationListening() bool {
	p.RLock()
	defer p.RUnlock()

	return p.appListening
}

// SetApplicationListening sets appListening.
func (p *PingConfig) SetApplicationListening(appListening bool) {
	p.Lock()
	defer p.Unlock()

	p.appListening = appListening
}

// SeqNum returns tcp sequence number.
func (p *PingConfig) SeqNum() uint32 {
	p.RLock()
	defer p.RUnlock()

	return p.seqNum
}

// SetSeqNum sets tcp sequence number.
func (p *PingConfig) SetSeqNum(seqNum uint32) {
	p.Lock()
	defer p.Unlock()

	p.seqNum = seqNum
}

// PingReport returns ping report.
func (p *PingConfig) PingReport() *collector.PingReport {
	p.RLock()
	defer p.RUnlock()

	return p.pingReport
}

// SetPingReport sets ping report.
func (p *PingConfig) SetPingReport(pingReport *collector.PingReport) {
	p.Lock()
	defer p.Unlock()

	p.pingReport = pingReport
}
