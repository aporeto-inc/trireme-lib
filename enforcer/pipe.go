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
	defer in.Close()
	defer syscall.Close(out)

	inFile, err := in.File()
	if err != nil {
		fmt.Printf("Internal error: %v", err)
		return fmt.Errorf("Internal error")
	}
	defer inFile.Close()
	defer syscall.Close(out)
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
		zap.L().Error("Read", zap.String("Direction", direction), zap.Int64("NumBytes", nread))
		if err != nil {
			zap.L().Error("49 = error splicing: %s - %v\n", zap.Error(err))
			return
		}
		if nread == 0 {
			break
		}
		var total int64
		for total = 0; total < nread; {
			nwrote, err := syscall.Splice(pipe[0], nil, destFd, nil, int(nread-total), 0)
			if err != nil {
				fmt.Printf("59 = error splicing: %s - %v", direction, err)
				return
			}
			total += nwrote
		}
	}

	// fmt.Printf("Done copying %s: %s -> %s", direction, src.RemoteAddr(), dest.RemoteAddr())
	syscall.Shutdown(srcFd, syscall.SHUT_RD)
	syscall.Shutdown(destFd, syscall.SHUT_WR)
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
