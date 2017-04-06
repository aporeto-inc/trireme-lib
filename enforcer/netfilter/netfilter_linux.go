// +build linux

/*
   Copyright 2014 Krishna Raman <kraman@gmail.com>
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/*Package netfilter provides Go bindings for libnetfilter_queue
This library provides access to packets in the IPTables netfilter queue (NFQUEUE).
The libnetfilter_queue library is part of the http://netfilter.org/projects/libnetfilter_queue/ project.
*/
package netfilter

/*
#cgo pkg-config: libnetfilter_queue
#cgo CFLAGS: -Wall -I/usr/include -DINCLUDE_IN_COMPILE
#cgo LDFLAGS: -L/usr/lib64/
#include "netfilter.h"
*/
import "C"

import (
	"fmt"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	log "github.com/Sirupsen/logrus"
)

type verdictType C.uint

const (
	//AfInet Address Family Inet
	AfInet = 2

	//NfDrop Net filter verdict
	NfDrop verdictType = C.uint(0)
	//NfAccept Net filter verdict
	NfAccept verdictType = C.uint(1)
	//NfStolen Net filter verdict
	NfStolen verdictType = C.uint(2)
	//NfQueue Net filter verdict
	NfQueue verdictType = C.uint(3)
	//NfRepeat Net filter verdict
	NfRepeat verdictType = C.uint(4)
	//NfStop Net filter verdict
	NfStop verdictType = C.uint(5)

	//NfDefaultPacketSize default packet size
	NfDefaultPacketSize uint32 = 0xffff

	// netlinkNoEnobufs is the number of buffers
	netlinkNoEnobufs = 5

	// solNetlink is the system call argument
	solNetlink = 270
)

//NFPacket structure holds the packet
type NFPacket struct {
	Buffer      []byte
	Mark        string
	Xbuffer     *C.uchar
	QueueHandle *C.struct_nfq_q_handle
	ID          int
}

//NFQueue implements the queue and holds all related state information
type NFQueue struct {
	h       *C.struct_nfq_handle
	qh      *C.struct_nfq_q_handle
	fd      C.int
	packets chan NFPacket
	idx     uint32
	Packets chan *NFPacket
}

// Verdict for a packet. Buffer is the original buffer of the packet
// Payload is any new data that have to be appended to the packet
type Verdict struct {
	V       verdictType
	Buffer  []byte
	Payload []byte
	Options []byte

	Xbuffer     *C.uchar
	ID          int
	QueueHandle *C.struct_nfq_q_handle
}

var theTable = make(map[uint32]*NFQueue, 0)

// NewNFQueue creates and bind to queue specified by queueID.
func NewNFQueue(queueID uint16, maxPacketsInQueue uint32, packetSize uint32) (*NFQueue, error) {
	var nfq = NFQueue{
		Packets: make(chan *NFPacket, 2000),
	}
	var err error
	var ret C.int

	if nfq.h, err = C.nfq_open(); err != nil {

		log.WithFields(log.Fields{
			"package": "netfilter",
			"error":   err.Error(),
		}).Debug("Error opening NFQueue handle")

		return nil, fmt.Errorf("Error opening NFQueue handle: %v ", err)
	}

	if ret, err = C.nfq_unbind_pf(nfq.h, AfInet); err != nil || ret < 0 {

		log.WithFields(log.Fields{
			"package": "netfilter",
			"error":   err.Error(),
		}).Debug("Error unbinding existing NFQ handler from AfInet protocol family")

		return nil, fmt.Errorf("Error unbinding existing NFQ handler from AfInet protocol family: %v ", err)
	}

	if ret, err = C.nfq_bind_pf(nfq.h, AfInet); err != nil || ret < 0 {

		log.WithFields(log.Fields{
			"package": "netfilter",
			"error":   err.Error(),
		}).Debug("Error binding to AfInet protocol family")

		return nil, fmt.Errorf("Error binding to AfInet protocol family: %v ", err)
	}

	nfq.idx = uint32(time.Now().UnixNano())

	// Create the queue

	if nfq.qh, err = C.CreateQueue(nfq.h, C.u_int16_t(queueID), C.u_int32_t(nfq.idx)); err != nil || nfq.qh == nil {
		C.nfq_close(nfq.h)

		log.WithFields(log.Fields{
			"package": "netfilter",
			"error":   err.Error(),
		}).Debug("Error binding to queue")

		return nil, fmt.Errorf("Error binding to queue: %v ", err)
	}

	// Set packets to copy mode - We need to investigate if we can avoid one copy
	// here.
	if C.nfq_set_mode(nfq.qh, C.u_int8_t(2), C.uint(packetSize)) < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)

		log.WithFields(log.Fields{
			"package": "netfilter",
			"error":   err.Error(),
		}).Debug("Unable to set packets copy mode")

		return nil, fmt.Errorf("Unable to set packets copy mode: %v ", err)
	}

	// Set the max length of the queue
	if ret, err = C.nfq_set_queue_maxlen(nfq.qh, C.u_int32_t(maxPacketsInQueue)); err != nil || ret < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)

		log.WithFields(log.Fields{
			"package": "netfilter",
			"error":   err.Error(),
		}).Debug("Unable to set max packets in queue")

		return nil, fmt.Errorf("Unable to set max packets in queue: %v ", err)
	}

	// Get the queue file descriptor
	if nfq.fd, err = C.nfq_fd(nfq.h); err != nil {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)

		log.WithFields(log.Fields{
			"package": "netfilter",
			"error":   err.Error(),
		}).Debug("Unable to get queue file-descriptor.")

		return nil, fmt.Errorf("Unable to get queue file-descriptor. %v", err)
	}

	netlinkHandle := C.nfq_nfnlh(nfq.h)
	C.nfnl_rcvbufsiz(netlinkHandle, C.uint(packetSize*maxPacketsInQueue))

	fd := C.nfnl_fd(netlinkHandle)
	opt := 1
	optionsError := setsockopt(int(fd), solNetlink, netlinkNoEnobufs, unsafe.Pointer(&opt), unsafe.Sizeof(opt))
	if optionsError != nil {
		log.WithFields(log.Fields{
			"package": "netfilter",
			"error":   optionsError.Error(),
		}).Error("Unable to get queue file-descriptor.")
	}

	theTable[nfq.idx] = &nfq

	go nfq.run()

	return &nfq, nil
}

//Close Unbind and close the queue
func (nfq *NFQueue) Close() {

	C.nfq_destroy_queue(nfq.qh)

	C.nfq_close(nfq.h)

	delete(theTable, nfq.idx)

}

// run just calls the Run function in the C space
func (nfq *NFQueue) run() {

	C.Run(nfq.h, nfq.fd)

}

// nolint : deadcode 
// export processPacket
func processPacket(packetID C.int, mark C.int, data *C.uchar, len C.int, newData *C.uchar, idx uint32) verdictType {

	nfq, ok := theTable[idx]
	if !ok {
		log.WithFields(log.Fields{
			"package": "netfilter",
			"idx":     idx,
		}).Debug("Dropping, unexpectedly due to bad idx=")

		return NfDrop
	}

	// Create a new packet and associated the pointers
	p := NFPacket{
		Buffer:      C.GoBytes(unsafe.Pointer(data), len),
		Xbuffer:     newData,
		ID:          int(packetID),
		Mark:        strconv.Itoa(int(mark)),
		QueueHandle: nfq.qh,
	}

	select {
	case nfq.Packets <- &p:
	default:
		log.WithFields(log.Fields{
			"package": "netfilter",
			"idx":     idx,
		}).Debug("Dropping packet - queue full ")
	}

	return 1
}

func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// SetVerdict receives the response from the processor, copies the buffers
// and passes the result to the C code
func SetVerdict(v *Verdict, mark int) int {

	var bufferLength int
	bufferLength = len(v.Buffer) + len(v.Options) + len(v.Payload)

	xbuf := (*[1 << 30]C.uchar)(unsafe.Pointer(v.Xbuffer))[:bufferLength:bufferLength] // nolint
	// Do the memcopy to the new packet format that must be transmitted
	// We need to use a new buffer since we are extending the packet
	// Do the memcopy to the new packet format that must be transmitted
	// We need to copy the data to the C allocated buffer

	length := 0
	for i := range v.Buffer {
		xbuf[i] = C.uchar(v.Buffer[i])
		length++
	}

	for i := range v.Options {
		xbuf[length] = C.uchar(v.Options[i])
		length++
	}

	for i := range v.Payload {
		xbuf[length] = C.uchar(v.Payload[i])
		length++
	}

	verdict := C.nfq_set_verdict2(v.QueueHandle, C.u_int32_t(v.ID), C.u_int32_t(v.V), C.u_int32_t(mark), C.u_int32_t(length), v.Xbuffer)

	return int(verdict)
}
