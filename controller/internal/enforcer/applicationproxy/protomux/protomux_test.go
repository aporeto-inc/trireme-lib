package protomux

import (
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestNetworkAddress(t *testing.T) {
	ip := networkOfAddress("172.17.0.2:80")
	assert.Equal(t, ip, "172.17.0.2", "ip should be 172.17.0.2")

	ip = networkOfAddress("[ff::1]:80")
	assert.Equal(t, ip, "ff::1", "ip should be ff::1")
}
