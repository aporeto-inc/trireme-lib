// +build linux

package tuntap

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
)

// TunTap -- struct to hold properties of tuntap devices.
type TunTap struct {
	numFramesRead []uint64
	DroppedFrames []uint64
	tuntap        DeviceType
	queueHandles  []int
	fdtoQueueNum  map[int]int
	numQueues     uint16
	ipAddress     string
	hwMacAddress  []byte
	deviceName    string
	uid           uint
	group         uint
	persist       bool
	epollfd       int
	queueCallBack func([]byte, interface{}) error
}

// NewTun -- creates a new tun interface and returns a handle to it. This will also implicitly bring up the interface
func NewTun(numQueues uint16, ipAddress string, macAddress []byte, deviceName string, uid uint, group uint, persist bool, callback func([]byte, interface{}) error) (*TunTap, error) {

	// NumQueues is 0 indexed gives us 256 queues
	if numQueues > 255 {
		return nil, fmt.Errorf("Max number of queues supported is 256")
	}
	if len(deviceName) > IFNAMSIZE {
		return nil, fmt.Errorf("Invalid device name. Max length is 16")
	}
	device := &TunTap{
		tuntap:        TUNDEVICE,
		numQueues:     numQueues,
		ipAddress:     ipAddress,
		hwMacAddress:  macAddress,
		queueHandles:  make([]int, numQueues+1),
		numFramesRead: make([]uint64, numQueues+1),
		DroppedFrames: make([]uint64, numQueues+1),
		fdtoQueueNum:  make(map[int]int, numQueues+1),
		deviceName:    deviceName,
		uid:           uid,
		group:         group,
		persist:       persist,
		queueCallBack: callback,
	}

	if err := device.setupTun(); err != nil {
		return nil, fmt.Errorf("Received error %s while creating device %s", err, deviceName)
	}

	if net.ParseIP(ipAddress) == nil && len(ipAddress) > 0 {
		device.ipAddress = "0.0.0.0"
	}

	return device, nil
}

// StartQueue starts the data loop for a tun queue.
// Wait for all goroutine to start sucessfully before continuing
func (t *TunTap) StartQueue(queueIndex int, privateData interface{}) {
	// TODO define constant or retrieve MTU of tun interface
	var data [75 * 1024]byte
	for {
		if n, err := t.ReadQueue(queueIndex, data[:]); err == nil {
			atomic.AddUint64(&t.numFramesRead[queueIndex], 1)
			if err = t.queueCallBack(data[:n], privateData); err != nil {
				atomic.AddUint64(&t.DroppedFrames[queueIndex], 1)
			}
			continue
		} else {
			zap.L().Error("Received Error while reading from queue to raw socket", zap.Error(err))
		}
	}

}

// ReadQueue -- Reads packets from a queue. This is a blocking read call. Returns num bytes read
func (t *TunTap) ReadQueue(queueNum int, data []byte) (int, error) {

	n, err := t.Read(t.queueHandles[queueNum], data)
	zap.L().Error("Reading queuenum ", zap.String("deviceName", t.deviceName), zap.Int("queueIndex", queueNum), zap.Int("FD", t.queueHandles[queueNum]))
	return n, err
}

func (t *TunTap) Read(fd int, data []byte) (int, error) {
	return read(fd, data)
}

// PollRead -- returns a list of queues on which data can be read
func (t *TunTap) PollRead(timeout int) ([]int, error) {
	var events [MaxEpollEvents]syscall.EpollEvent
	var fds [MaxEpollEvents]int
	_, err := syscall.EpollWait(t.epollfd, events[:], timeout)
	if err != nil {
		return []int{}, fmt.Errorf("Poll Wait Error %s", err)
	}
	for i, event := range events {
		syscall.SetNonblock(int(event.Fd), true)
		fds[i] = t.fdtoQueueNum[int(event.Fd)]
	}
	return fds[:], nil
}

// Write to write tun tap. Not Implemented as of now here
func (t *TunTap) Write(queueNum int, data []byte) (int, error) {
	return 0, nil
}

// setupTun -- create the Tun Interface.
func (t *TunTap) setupTun() error {
	ifname := &ifreqDevType{
		ifrFlags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
	}
	var err error
	//on Error anywhere close all queues and exit
	defer func() {
		if err != nil {
			for i := 0; i < int(t.numQueues); i++ {
				if t.queueHandles[i] != 0 {
					syscall.Close(t.queueHandles[i])
				}
			}
		}
	}()

	copy(ifname.ifrName[:], []byte(t.deviceName))

	for i := 0; i < int(t.numQueues); i++ {
		if err = t.createTun(i, ifname); err != nil {
			return err
		}
	}
	//set ip address for the interface
	if err = t.setipaddress(); err != nil {
		return err
	}
	if err = t.setInterfaceState(IFF_UP | IFF_RUNNING); err != nil {
		return err
	}
	return nil

}

// createTun creates a queue on the tun device.
func (t *TunTap) createTun(queueIndex int, ifname *ifreqDevType) error {
	if fd, err := syscall.Open(TUNCHARDEVICEPATH, syscall.O_RDWR, 0644); err == nil {

		if err = ioctl(uintptr(uintptr(fd)), syscall.TUNSETIFF, uintptr(unsafe.Pointer(ifname))); err != nil {
			return fmt.Errorf("Device Create Error %s", err)
		}

		// set owner
		if err = t.setOwner(fd); err != nil {
			return err
		}

		// set group
		if err = t.setGroup(fd); err != nil {
			return err
		}

		// set persistence state
		if err = t.setPersist(fd); err != nil {
			return err
		}

		t.queueHandles[queueIndex] = fd
		zap.L().Error("Created fd for queue ", zap.String("DeviceName", string(ifname.ifrName[:])), zap.Int("queueIndex", queueIndex), zap.Int("FD", fd))
		t.fdtoQueueNum[fd] = queueIndex
	} else {
		return err
	}
	return nil
}

//setipaddress -- sets the ip address of the tun interface. netmask is assumed to be 255.255.255.0
func (t *TunTap) setipaddress() error {

	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP); err == nil {
		defer syscall.Close(fd)
		address := syscall.RawSockaddrInet4{
			Family: syscall.AF_INET,
		}

		copy(address.Addr[:], net.ParseIP(t.ipAddress).To4())
		ifreq := &ifReqIPAddress{
			ipAddress: address,
		}
		copy(ifreq.ifrName[:], []byte(t.deviceName))
		if err = ioctl(uintptr(fd), syscall.SIOCSIFADDR, uintptr(unsafe.Pointer(ifreq))); err != nil {
			return fmt.Errorf("Received Error %s while setting ip address for device %s", err, t.ipAddress)
		}

		address = syscall.RawSockaddrInet4{
			Family: syscall.AF_INET,
		}
		copy(address.Addr[:], net.ParseIP("255.255.255.0").To4())
		ifreq = &ifReqIPAddress{
			ipAddress: address,
		}
		copy(ifreq.ifrName[:], []byte(t.deviceName))
		if err = ioctl(uintptr(fd), syscall.SIOCSIFNETMASK, uintptr(unsafe.Pointer(ifreq))); err != nil {
			return fmt.Errorf("Received Error %s while setting ip mask for device %s", err, t.ipAddress)
		}

	} else {
		return err
	}
	return nil
}

// setInterfaceState -- sets the interface state to up
func (t *TunTap) setInterfaceState(flags DeviceFlags) error {
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP); err == nil {
		ifinname := &ifreqDevType{}
		copy(ifinname.ifrName[:], []byte(t.deviceName))
		if err = ioctl(uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(ifinname))); err != nil {
			return fmt.Errorf("Received error %s while retrieving %s devce configs", err, t.deviceName)
		}
		ifname := &ifreqDevType{
			ifrFlags: ifinname.ifrFlags | flags,
		}
		copy(ifname.ifrName[:], []byte(t.deviceName))
		if err = ioctl(uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(ifname))); err != nil {
			return fmt.Errorf("Received error %s while setting %s devce configs", err, t.deviceName)
		}

	} else {
		return err
	}
	return nil

}

// setOwner -- sets the uid owner of the tun device
func (t *TunTap) setOwner(fd int) error {
	if err := ioctl(uintptr(uintptr(fd)), syscall.TUNSETOWNER, uintptr(t.uid)); err != nil {
		return fmt.Errorf("Device SetOwner Error %s", err)
	}

	return nil
}

// setGroup -- sets the gid owner of the tun device
func (t *TunTap) setGroup(fd int) error {

	if err := ioctl(uintptr(uintptr(fd)), syscall.TUNSETGROUP, uintptr(t.group)); err != nil {
		return fmt.Errorf("Device SetGroup Error %s", err)
	}
	return nil
}

// setPersist -- makes the tun device persistent/non-persistent
func (t *TunTap) setPersist(fd int) error {
	if t.persist {
		if err := ioctl(uintptr(uintptr(fd)), syscall.TUNSETPERSIST, uintptr(1)); err != nil {
			return fmt.Errorf("Device Persist Error %s", err)
		}

	} else {
		if err := ioctl(uintptr(uintptr(fd)), syscall.TUNSETPERSIST, uintptr(0)); err != nil {
			return fmt.Errorf("Device Persist Error %s", err)
		}
	}

	return nil
}
