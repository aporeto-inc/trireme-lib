// +build !linux

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

import "C"

type verdictType uint

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
	Buffer      []byte
	Mark        string
	Xbuffer     *C.uchar
	QueueHandle *C.struct_nfq_q_handle
	ID          int
}

//NFQueue implements the queue and holds all related state information
type NFQueue struct {
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

// NewNFQueue creates and bind to queue specified by queueID.
func NewNFQueue(queueID uint16, maxPacketsInQueue uint32, packetSize uint32) (*NFQueue, error) {

	return nil, nil
}

//Close Unbind and close the queue
func (nfq *NFQueue) Close() {

}

// run just calls the Run function in the C space
func (nfq *NFQueue) run() {

}

// SetVerdict creates a verdict
func SetVerdict(v *Verdict, mark int) int {
	return 0
}
