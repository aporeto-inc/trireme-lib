// +build linux

package markedconn

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
)

func TestGetOrigDestV4(t *testing.T) {

	message := "Hi there!\n"

	client := func() {
		tcpAddr, _ := net.ResolveTCPAddr("tcp", "localhost:3000")

		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return
		}

		defer conn.Close() //nolint

		if _, err := fmt.Fprintf(conn, message); err != nil { //nolint
			return
		}

		ip, port, _ := GetOriginalDestination(conn)
		assert.Equal(t, ip.String(), "127.0.0.1", "ip should be 127.0.0.1")
		assert.Equal(t, port, 3000, "port should be 3000")
	}

	server := func() {
		addr, err := net.ResolveTCPAddr("tcp", ":3000")
		if err != nil {
			return
		}

		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return
		}

		defer l.Close() //nolint
		conn, err := l.AcceptTCP()
		if err != nil {
			return
		}
		ip, port, _ := GetOriginalDestination(conn)
		assert.Equal(t, ip.String(), "127.0.0.1", "ip should be 127.0.0.1")
		assert.Equal(t, port, 3000, "port should be 3000")
		defer conn.Close() //nolint

		_, err = ioutil.ReadAll(conn)
		if err != nil {
			return
		}
	}

	go server()
	time.Sleep(1 * time.Second)
	go client()

	time.Sleep(5 * time.Second)
}

func TestLocalAddr(t *testing.T) {
	ip, _, _ := net.ParseCIDR("172.17.0.2/24")
	proxyConn := ProxiedConnection{originalIP: ip, originalPort: 80}

	naddr := proxyConn.LocalAddr()
	netAddr := naddr.(*net.TCPAddr)

	assert.Equal(t, ip, netAddr.IP, "ip should be equal to 172.17.0.2")
	assert.Equal(t, 80, netAddr.Port, "ip should be equal to 172.17.0.2")
}

func TestSocketListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background()) //nolint
	_, err := NewSocketListener(ctx, ":1111", 100)

	assert.Equal(t, err, nil, "error  should be nil")
	cancel() //nolint
}

func TestGetInterfaces(t *testing.T) {

	ipmap := GetInterfaces()

	b := len(ipmap) != 0
	assert.Equal(t, b, true, "ipmap should not be empty")
}
