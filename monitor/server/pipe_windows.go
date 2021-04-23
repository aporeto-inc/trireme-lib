// +build windows

package server

import (
	"fmt"
	"net"
	"os/user"
	"strings"

	winio "github.com/Microsoft/go-winio"
	zap "go.uber.org/zap"
)

const pipePrefix = `\\.\pipe\`

func cleanupPipe(address string) error {
	return nil
}

func makePipe(address string) (net.Listener, error) {
	var pipeListener net.Listener
	var err error

	pipeName := address
	if !strings.HasPrefix(pipeName, pipePrefix) {
		pipeName = pipePrefix + pipeName
	}

	pipeCfg := &winio.PipeConfig{}

	current, err := user.Current()
	if err != nil {
		zap.L().Error("Unable to get the current user", zap.String("address", address), zap.Error(err))
		return nil, err
	}

	// A discretionary access control list (DACL) identifies the trustees that are allowed or denied access to a securable object.
	// D:P(A;;GA;;;SY)(A;;GA;;;BA) = DACL allowing (A) General all access (GA) for SYSTEM (SY), Admin (BA) and current user.
	// This library is creating the pipe using undocumented kernel functions instead of using the win32 functions.
	// So if the code is running as the administrator, then the security descriptor works just fine, but
	// if you are running as a non admin even if you are in the administrator's group, then you don't get access to the pipe,
	// and that is why the code is also granting access to the current user.  Normally you would not need to do this.

	pipeCfg.SecurityDescriptor = fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)", current.Uid)

	pipeListener, err = winio.ListenPipe(pipeName, pipeCfg)

	if err != nil {
		zap.L().Error("Unable to start the listener", zap.String("address", address), zap.Error(err))
		return nil, err
	}
	return pipeListener, nil
}
