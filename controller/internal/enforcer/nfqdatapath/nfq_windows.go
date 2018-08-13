// +build windows

package nfqdatapath

import (
	"context"
	"sync"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/windatapath"

	"go.uber.org/zap"
)

const (
	networkFilter = "inbound"
	appFilter     = "outbound"
)

func errorCallback(err error, data interface{}) {
	zap.L().Error("Error while processing packets on queue", zap.Error(err))
}
func networkCallback(packet []byte, d interface{}) {
	d.(*Datapath).processNetworkPacketsFromWindivert(packet)
}

func appCallBack(packet []byte, d interface{}) {
	d.(*Datapath).processApplicationPacketsFromWinDivert(packet)
}

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *Datapath) startNetworkInterceptor(ctx context.Context) {
	var wg sync.WaitGroup
	if hdl, err := windatapath.NewWindatapath(); err != nil {
		zap.L().Fatal("Unable to start windatapath", zap.Error(err))
	} else {

		if datapathhdl, err := hdl.WinDivertOpen(networkFilter, 0, 0, 0); err != nil {
			zap.L().Fatal("Failed to open windivert device", zap.Error(err))
		}
		data := make([]byte, 64*1024)
		recvAddr := C.WINDIVERT_ADDRESS{}
		var packetlen uint
		for {

			if err := hdl.WinDivertRecv(data, datapathhdl, recvAddr, &packetLen); err != nil {
				zap.L().Error("Cannot received packets", zap.Error(err))
				continue
			}
			networkCallback(data, d)
		}
	}
	return

}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *Datapath) startApplicationInterceptor(ctx context.Context) {
	if hdl, err := windatapath.NewWindatapath(); err != nil {
		zap.L().Fatal("Unable to start windatapath", zap.Error(err))
	} else {

		if _, err := hdl.WinDivertOpen(appFilter, 0, 0, 0); err != nil {
			zap.L().Fatal("Failed to open windivert device", zap.Error(err))
		}
		data := make([]byte, 64*1024)
		recvAddr := C.WINDIVERT_ADDRESS{}
		var packetlen uint
		for {

			if err := hdl.WinDivertRecv(data, datapathhdl, recvAddr, &packetLen); err != nil {
				zap.L().Error("Cannot received packets", zap.Error(err))
				continue
			}
			appCallback(data, d)
		}
	}

}

func (d *Datapath)processApplicationPacketsFromWinDivert(packet [][byte,d interface]{}) {
	return
}

func (d *Datapath)processNetworkPacketsFromWindivert(packet []byte,d interface{}) {
	return
}
/* func createAndStartReceiver(ctx context.Context, windatpathhandle uintptr, network bool, callback func([]byte, interface{}, sync.WaitGroup)) {
	data := make([]byte, 64*1024)
	recvAddr := C.WINDIVERT_ADDRESS{}
	var packetlen uint
	wg.Add(1)
	go func() {
		for {
			handle.WinDivertRecv(data, handle, &recvAddr, &packetlen)
			fmt.Println(hex.Dump(data[:packetlen]))
			var writeLen uint
			WinDivertSend(dllhdl, handle, data[:packetlen], &recvAddr, &writeLen)
		}
		wg.Done()
	}()

} */
