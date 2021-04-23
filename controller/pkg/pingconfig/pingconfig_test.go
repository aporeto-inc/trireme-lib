package pingconfig

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
)

func Test_NewPingConfig(t *testing.T) {

	p := New()
	require.NotNil(t, p)

	p.SetSocketFd(4)
	require.Equal(t, uintptr(4), p.SocketFd())

	p.SetSocketClosed(true)
	require.True(t, p.SocketClosed())

	p.SetPingID("abc")
	require.Equal(t, "abc", p.PingID())

	p.SetIterationID(2)
	require.Equal(t, 2, p.IterationID())

	p.SetApplicationListening(true)
	require.True(t, p.ApplicationListening())

	p.SetSeqNum(2323)
	require.Equal(t, uint32(2323), p.SeqNum())

	pr := &collector.PingReport{PingID: "xyz"}
	p.SetPingReport(pr)
	require.Equal(t, pr, p.PingReport())
}
