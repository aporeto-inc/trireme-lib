// +build linux

package connproc

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
)

const (
	sockOptOriginalDst = 80
)

type sockaddr struct {
	family uint16
	data   [14]byte
}

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// GetOriginalDestination -- Func to get original destination a connection
func GetOriginalDestination(conn net.Conn) (net.IP, int, error) {
	var addr sockaddr
	size := uint32(unsafe.Sizeof(addr))

	inFile, err := conn.(*net.TCPConn).File()
	if err != nil {
		return []byte{}, 0, err
	}

	err = getsockopt(int(inFile.Fd()), syscall.SOL_IP, sockOptOriginalDst, uintptr(unsafe.Pointer(&addr)), &size)
	if err != nil {
		return []byte{}, 0, err
	}

	if addr.family != syscall.AF_INET {
		return []byte{}, 0, fmt.Errorf("invalid address family")
	}

	var ip net.IP
	ip = addr.data[2:6]
	port := int(addr.data[0])<<8 + int(addr.data[1])

	return ip, port, nil
}

// GetInterfaces retrieves all the local interfaces.
func GetInterfaces() map[string]struct{} {
	ipmap := map[string]struct{}{}

	ifaces, _ := net.Interfaces()
	for _, intf := range ifaces {
		addrs, _ := intf.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.To4() != nil {
				ipmap[ip.String()] = struct{}{}
			}
		}
	}
	return ipmap
}

// Fd returns the Fd of a connection
func Fd(c net.Conn) (*os.File, int, error) {
	inTCP, ok := c.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("No support for non TCP")
	}

	inFile, err := inTCP.File()
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to open file: %s", err)
	}

	return inFile, int(inFile.Fd()), nil
}

// WriteMsg writes a message to the provided Fd
func WriteMsg(fd int, data []byte) error {
	addr, err := syscall.Getpeername(fd)
	if err != nil {
		return fmt.Errorf("Cannot retrieve peer name %s %+v", err, addr)
	}

	return syscall.Sendto(fd, data, 0, addr)
}

// ReadMsg reads a message from the provided Fd
func ReadMsg(fd int) (int, []byte, error) {
	msg := make([]byte, 2048)
	n, _, err := syscall.Recvfrom(fd, msg, 0)
	return n, msg, err
}

// Pipe proxies data bi-directionally between in and out.
func Pipe(ctx context.Context, inConn, outConn net.Conn) error {

	inFile, inFd, err := Fd(inConn)
	if err != nil {
		return err
	}
	defer inFile.Close() // nolint

	outFile, outFd, err := Fd(outConn)
	if err != nil {
		return err
	}
	defer outFile.Close() // nolint

	var wg sync.WaitGroup
	wg.Add(2)

	go copyBytes(ctx, "from backend", inFd, outFd, &wg)
	go copyBytes(ctx, "to backend", outFd, inFd, &wg)
	wg.Wait()
	return nil
}

func copyBytes(ctx context.Context, direction string, destFd, srcFd int, wg *sync.WaitGroup) {
	defer wg.Done()

	pipe := []int{0, 0}
	err := syscall.Pipe2(pipe, syscall.O_CLOEXEC)
	if err != nil {
		zap.L().Error("error creating splicing:", zap.String("Direction", direction), zap.Error(err))
		return
	}
	defer func() {
		// This is closed already. That's how we came here.
		syscall.Shutdown(srcFd, syscall.SHUT_RD) // nolint

		if err = syscall.Shutdown(destFd, syscall.SHUT_WR); err != nil {
			zap.L().Error("Could Not Close Dest Pipe")
		}

		if err = syscall.Close(pipe[0]); err != nil {
			zap.L().Warn("Failed to close pipe ", zap.Error(err))
		}
		if err = syscall.Close(pipe[1]); err != nil {
			zap.L().Warn("Failed to close pipe ", zap.Error(err))
		}
	}()

	for {
		select {
		case <-ctx.Done():
			break
		default:
			nread, serr := syscall.Splice(srcFd, nil, pipe[1], nil, 8192, 0)
			if serr != nil {
				zap.L().Error("error splicing: %s - %v\n", zap.Error(serr))
				return
			}
			if nread == 0 {
				return
			}
			var total int64
			for total = 0; total < nread; {
				var nwrote int64
				if nwrote, err = syscall.Splice(pipe[0], nil, destFd, nil, int(nread-total), 0); err != nil {
					zap.L().Error("error splicing:", zap.String("Direction", direction), zap.Error(err))
					return
				}
				total += nwrote
			}
		}
	}
}
