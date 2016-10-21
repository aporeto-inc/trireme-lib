// +build linux,!darwin

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
	"time"
	"unsafe"

	"github.com/golang/glog"
)

type verdictType C.uint

const (
	//AfInet Address Family Inet
	AfInet = 2

	//NfDrop Net filter verdict
	NfDrop verdictType = 0
	//NfAccept Net filter verdict
	NfAccept verdictType = 1
	//NfStolen Net filter verdict
	NfStolen verdictType = 2
	//NfQueue Net filter verdict
	NfQueue verdictType = 3
	//NfRepeat Net filter verdict
	NfRepeat verdictType = 4
	//NfStop Net filter verdict
	NfStop verdictType = 5

	//NfDefaultPacketSize default packet size
	NfDefaultPacketSize uint32 = 0xffff
)

//NFPacket structure holds the packet
type NFPacket struct {
	Buffer []byte
}

//NFQueue implements the queue and holds all related state information
type NFQueue struct {
	h         *C.struct_nfq_handle
	qh        *C.struct_nfq_q_handle
	fd        C.int
	packets   chan NFPacket
	idx       uint32
	processor func(*NFPacket) *Verdict
}

// Verdict for a packet. Buffer is the original buffer of the packet
// Payload is any new data that have to be appended to the packet
type Verdict struct {
	V       verdictType
	Buffer  []byte
	Payload []byte
	Options []byte
}

var theTable = make(map[uint32]*NFQueue, 0)

// NewNFQueue creates and bind to queue specified by queueID.
func NewNFQueue(queueID uint16, maxPacketsInQueue uint32, packetSize uint32, processor func(*NFPacket) *Verdict) (*NFQueue, error) {
	var nfq = NFQueue{}
	var err error
	var ret C.int

	if nfq.h, err = C.nfq_open(); err != nil {
		return nil, fmt.Errorf("Error opening NFQueue handle: %v\n", err)
	}

	if ret, err = C.nfq_unbind_pf(nfq.h, AfInet); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error unbinding existing NFQ handler from AfInet protocol family: %v\n", err)
	}

	if ret, err = C.nfq_bind_pf(nfq.h, AfInet); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error binding to AfInet protocol family: %v\n", err)
	}

	nfq.idx = uint32(time.Now().UnixNano())

	nfq.processor = processor

	// Create the queue

	if nfq.qh, err = C.CreateQueue(nfq.h, C.u_int16_t(queueID), C.u_int32_t(nfq.idx)); err != nil || nfq.qh == nil {
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Error binding to queue: %v\n", err)
	}

	// Set the max length of the queue
	if ret, err = C.nfq_set_queue_maxlen(nfq.qh, C.u_int32_t(maxPacketsInQueue)); err != nil || ret < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to set max packets in queue: %v\n", err)
	}

	// Set packets to copy mode - We need to investigate if we can avoid one copy
	// here.
	if C.nfq_set_mode(nfq.qh, C.u_int8_t(2), C.uint(packetSize)) < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to set packets copy mode: %v\n", err)
	}

	// Get the queue file descriptor
	if nfq.fd, err = C.nfq_fd(nfq.h); err != nil {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("Unable to get queue file-descriptor. %v", err)
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

//export processPacket
func processPacket(queueID C.int, data *C.uchar, len C.int, newData *C.uchar, newLength *C.int, idx uint32) verdictType {

	// Translate the C pointer to an array that can be handled in the C space
	xbuf := (*[1 << 30]C.uchar)(unsafe.Pointer(newData))[:int(*newLength):int(*newLength)]

	// Create a new packet and associated the pointers
	p := NFPacket{
		Buffer: C.GoBytes(unsafe.Pointer(data), len),
	}

	nfq, ok := theTable[idx]

	if !ok {
		glog.V(5).Infoln("Dropping, unexpectedly due to bad idx=", idx)
		return NfDrop
	}

	v := nfq.processor(&p)

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

	// The C side needs the actuall length. It can't figure this out from the buffer size
	*newLength = C.int(length)

	return verdictType(v.V)

}
