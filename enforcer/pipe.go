package enforcer

import (
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
		return fmt.Errorf("Internal error %s", err.Error())
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
	defer syscall.Close(pipe[0])
	defer syscall.Close(pipe[1])

	for {
		nread, err := syscall.Splice(srcFd, nil, pipe[1], nil, 8192, 0)
		if err != nil {
			zap.L().Error("error splicing: %s - %v\n", zap.Error(err))
			return
		}
		if nread == 0 {
			break
		}
		var total int64
		for total = 0; total < nread; {
			nwrote, err := syscall.Splice(pipe[0], nil, destFd, nil, int(nread-total), 0)
			if err != nil {
				fmt.Printf("error splicing: %s - %v", direction, err)
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
