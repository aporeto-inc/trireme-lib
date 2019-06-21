// +build linux

package markedconn

import (
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/magiconair/properties/assert"
)

func testGetOrigDestV4(t *testing.T) {

	message := "Hi there!\n"

	testGetOrigV4 := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
		sa := (*(*sockaddr4)(unsafe.Pointer(a4))) //nolint
		sa.family = syscall.AF_INET
		copy(sa.data[2:6], []byte{127, 0, 0, 1})
		binary.BigEndian.PutUint16(sa.data[:2], 3000)
		*(*sockaddr4)(unsafe.Pointer(a4)) = sa //nolint
		return 0, 0, 0
	}

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
		ip, port, _ := GetOriginalDestination(conn, testGetOrigV4)
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

func testGetOrigDestV6(t *testing.T) {

	message := "Hi there!\n"

	testGetOrigV6 := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
		sa := (*(*sockaddr6)(unsafe.Pointer(a4))) //nolint
		sa.family = syscall.AF_INET6

		copy(sa.ip[:], net.ParseIP("::1"))
		binary.BigEndian.PutUint16(sa.port[:], 3000)

		*(*sockaddr6)(unsafe.Pointer(a4)) = sa //nolint
		return 0, 0, 0
	}

	client := func() {
		tcpAddr, _ := net.ResolveTCPAddr("tcp6", "[::1]:3000")

		conn, err := net.DialTCP("tcp6", nil, tcpAddr)
		if err != nil {
			return
		}

		defer conn.Close() //nolint

		if _, err := fmt.Fprintf(conn, message); err != nil { //nolint
			return
		}
	}

	server := func() {
		addr, err := net.ResolveTCPAddr("tcp6", "[::1]:3000")
		if err != nil {
			return
		}

		l, err := net.ListenTCP("tcp6", addr)
		if err != nil {
			return
		}

		defer l.Close() //nolint
		conn, err := l.AcceptTCP()
		if err != nil {
			return
		}

		ip, port, _ := GetOriginalDestination(conn, testGetOrigV6) //nolint
		assert.Equal(t, ip.String(), "::1", "ip should be ::1")
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

var m sync.Mutex

func TestOrigDest(t *testing.T) {
	m.Lock()
	testGetOrigDestV4(t)
	m.Unlock()

	m.Lock()
	testGetOrigDestV6(t)
	m.Unlock()
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
