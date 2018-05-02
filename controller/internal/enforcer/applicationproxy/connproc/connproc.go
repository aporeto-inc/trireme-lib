// +build linux

package connproc

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/applicationproxy/markedconn"
	"go.uber.org/zap"
)

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
	var inTCP *net.TCPConn

	switch c.(type) {
	case *net.TCPConn:
		inTCP = c.(*net.TCPConn)
	case *markedconn.ProxiedConnection:
		inTCP = c.(*markedconn.ProxiedConnection).GetTCPConnection()
	default:
		return nil, 0, fmt.Errorf("Unprocessable connection")
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

	go copyBytes(ctx, "incoming", inFd, outFd, &wg)
	go copyBytes(ctx, "outgoing", outFd, inFd, &wg)
	wg.Wait()
	if err := outConn.Close(); err != nil {
		fmt.Println("inconn close", err)
	}
	if err := inConn.Close(); err != nil {
		fmt.Println("inconn close", err)
	}

	return nil
}

func copyBytes(ctx context.Context, direction string, destFd, srcFd int, wg *sync.WaitGroup) {
	var total int64
	var nwrote int64

	pipe := []int{0, 0}
	err := syscall.Pipe2(pipe, syscall.O_CLOEXEC)
	if err != nil {
		zap.L().Error("error creating splicing:", zap.String("Direction", direction), zap.Error(err))
		wg.Done()
		return
	}
	defer func() {
		if err = syscall.Shutdown(destFd, syscall.SHUT_WR); err != nil {
			if er, ok := err.(syscall.Errno); ok {
				if er != syscall.ENOTCONN {
					zap.L().Warn("closing connection failed:", zap.String("Direction", direction), zap.Error(err))
				}
			}
		}
		if err = syscall.Close(pipe[0]); err != nil {
			zap.L().Warn("Failed to close pipe ", zap.Error(err))
		}
		if err = syscall.Close(pipe[1]); err != nil {
			zap.L().Warn("Failed to close pipe ", zap.Error(err))
		}
		wg.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			break
		default:
			nread, serr := syscall.Splice(srcFd, nil, pipe[1], nil, 16384, 0)
			if serr != nil {
				if er, ok := serr.(syscall.Errno); ok {
					if er == syscall.ECONNRESET || er == syscall.ECONNABORTED || er == syscall.ENOTCONN {
						return
					}
					zap.L().Error("error splicing:", zap.String("Direction", direction), zap.Error(serr))
					return
				}
				return
			}
			if nread == 0 {
				return
			}
			for total = 0; total < nread; {
				if nwrote, err = syscall.Splice(pipe[0], nil, destFd, nil, int(nread-total), 0); err != nil {
					if er, ok := serr.(syscall.Errno); ok {
						if er == syscall.ECONNRESET || er == syscall.ECONNABORTED || er == syscall.ENOTCONN {
							return
						}
						zap.L().Error("error splicing:", zap.String("Direction", direction), zap.Error(serr))
						return
					}
				}
				total += nwrote
			}
		}
	}
}
