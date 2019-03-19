package flowtracking

import (
	"net"
	"testing"
)

func Test_ReverseFlowUpdate(t *testing.T) {

	dest := net.ParseIP("192.168.100.103")

	src := net.ParseIP("172.17.0.3")

	err := UpdateNetworkFlowMark(src, dest, 6, 80, 48824, 100)
	if err != nil {
		t.Errorf("Failed to update entry: %s", err)
	}

}

// func Test_ForwardFlow(t *testing.T) {
// 	src := net.ParseIP("10.0.2.15")

// 	dst := net.ParseIP("10.0.2.2")

// 	err := UpdateApplicationFlowMark(src, dst, 6, 22, 63831, 2)
// 	if err != nil {
// 		t.Errorf("Failed to update entry: %s", err)
// 	}
// }
