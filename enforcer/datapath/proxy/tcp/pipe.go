//+build linux

package tcp

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"

	"go.uber.org/zap"
)

// Pipe proxies data bi-directionally between in and out.
func Pipe(in *net.TCPConn, out int) error {
	defer func() {
		if err := in.Close(); err != nil {
			zap.L().Error("Failed to close inFile")
		}
		if err := syscall.Close(out); err != nil {
			zap.L().Error("Failed to close outFile")
		}
	}()

	inFile, err := in.File()
	if err != nil {
		return err
	}
	defer func() {
		if err := inFile.Close(); err != nil {
			zap.L().Error("Failed to close inFile")
		}
		if err := syscall.Close(out); err != nil {
			zap.L().Error("Failed to close outFile")
		}
	}()
	inFd := int(inFile.Fd())

	var wg sync.WaitGroup
	wg.Add(2)

	go copyBytes("from backend", inFd, out, &wg)
	go copyBytes("to backend", out, inFd, &wg)
	wg.Wait()
	return nil
}

func copyBytes(direction string, destFd, srcFd int, wg *sync.WaitGroup) {
	defer wg.Done()

	pipe := []int{0, 0}
	err := syscall.Pipe2(pipe, syscall.O_CLOEXEC)
	if err != nil {
		fmt.Printf("error creating pipe: %v", err)
		return
	}
	defer func() {
		if err = syscall.Close(pipe[0]); err != nil {
			zap.L().Warn("Failed to close pipe ", zap.Error(err))
		}
		if err = syscall.Close(pipe[1]); err != nil {
			zap.L().Warn("Failed to close pipe ", zap.Error(err))
		}

	}()

	for {
		nread, serr := syscall.Splice(srcFd, nil, pipe[1], nil, 8192, 0)
		if serr != nil {
			zap.L().Error("error splicing: %s - %v\n", zap.Error(serr))
			return
		}
		if nread == 0 {
			break
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

	if err = syscall.Shutdown(srcFd, syscall.SHUT_RD); err != nil {
		zap.L().Error("Could Not Close Source Pipe")
	}
	if err = syscall.Shutdown(destFd, syscall.SHUT_WR); err != nil {
		zap.L().Error("Could Not Close Dest Pipe")
	}
}

// CopyPipe -- Copies in case splice is not possible
func CopyPipe(a, b net.Conn) error {
	done := make(chan error, 1)

	cp := func(r, w net.Conn) {
		_, err := io.Copy(r, w)
		done <- err
	}

	go cp(a, b)
	go cp(b, a)
	err1 := <-done
	err2 := <-done
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}

func copyEncryptedFlow(tlsConn *tls.Conn, fd int) error {
	defer func() {
		if err := tlsConn.Close(); err != nil {
			zap.L().Error("Failed to close TLS Connection", zap.Error(err))
		}
		if err := syscall.Close(fd); err != nil {
			zap.L().Error("Cannot Close socket to application", zap.Error(err))
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		readSlice := make([]byte, 1024)
		//from tlsConn --> fd

		for {
			if n, err := tlsConn.Read(readSlice); err == nil {
				if n > 0 {
					if n, err = syscall.Write(fd, readSlice[:n]); err != nil {
						continue
					}
				}

			}

		}
	}()

	go func() {
		defer wg.Done()
		//fd --> tlsConn
		readSlice := make([]byte, 1024)
		events := make([]syscall.EpollEvent, 1)
		if err := syscall.SetNonblock(fd, true); err != nil {
			zap.L().Error("Cannot put socket in non-blocking mode")
		}
		var epfd int
		var epollerr error
		if epfd, epollerr = syscall.EpollCreate1(0); epollerr != nil {
			zap.L().Error("Unable to create epoll set")
			return
		}
		defer syscall.Close(epfd) // nolint
		for {
			if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(fd)}); err != nil {
				zap.L().Error("Cannot add socket to epoll wait", zap.Error(err))
			}
			n, err := syscall.EpollWait(epfd, events, 10)
			if n, err := syscall.Read(fd, readSlice); err == nil {
				if n, err = tlsConn.Write(readSlice[:n]); err != nil {
					zap.L().Debug("Could Not Write Data to remote")
				}
			}
		}
	}()
	wg.Wait()
	return nil
}
