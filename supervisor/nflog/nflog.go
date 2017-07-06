// +build linux !darwin

// Use cgo to interface with nflog
//
// Docs: http://www.netfilter.org/projects/libnetfilter_log/doxygen/index.html
//
// Debian packages needed:
//   apt-get install iptables-dev linux-libc-dev libnetfilter-log-dev

package nflog

import (
	"log"
	"net"
	"reflect"
	"syscall"
	"unsafe"
)

/*
#cgo LDFLAGS: -lnfnetlink -lnetfilter_log
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <inttypes.h>

// A record of each packet
typedef struct {
	char *payload;
	int payload_len;
	u_int32_t seq;
} packet;

// Max number of packets to collect at once
#define MAX_PACKETS (16*1024)

// A load of packets with count
typedef struct {
	int index;
	packet pkt[MAX_PACKETS];
} packets;

// Process the incoming packet putting pointers to the data to be handled by Go
static int _processPacket(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfd, void *data) {
	packets *ps = (packets *)data;
	if (ps->index >= MAX_PACKETS) {
		return 1;
	}
	packet *p = &ps->pkt[ps->index++];
	p->payload = 0;
	p->payload_len = nflog_get_payload(nfd, &p->payload);
	p->seq = 0;
	nflog_get_seq(nfd, &p->seq);
	return 0;
 }

// Register the callback - can't be done from Go
//
// We have to register a C function _processPacket
static int _callback_register(struct nflog_g_handle *gh, packets *data) {
	return nflog_callback_register(gh, _processPacket, data);
}

// A thin shim to call nflog_bind_group to work around the changes to
// the type of num
static struct nflog_g_handle *_nflog_bind_group(struct nflog_handle *h, int num) {
    return nflog_bind_group(h, num);
}
*/
import "C"

const (
	RecvBufferSize   = 4 * 1024 * 1024
	NflogBufferSize  = 128 * 1024 // Must be <= 128k (checked in kernel source)
	NfRecvBufferSize = 16 * 1024 * 1024
	NflogTimeout     = 100 // Timeout before sending data in 1/100th second
	MaxQueueLogs     = C.MAX_PACKETS - 1
)

// Current nflog error
func nflogError(err error) error {
	if C.nflog_errno != 0 {
		return syscall.Errno(C.nflog_errno)
	}
	return err
}

// NfLog
type nfLog struct {
	packetsToProcess chan []Packet
	processedPackets chan []Packet
	addPackets       []Packet
	direction        IPDirection
	errors           int64
	fd               C.int
	gh               *C.struct_nflog_g_handle
	h                *C.struct_nflog_handle
	ipPacket         *IPPacketInfo
	ipVersion        byte
	mask             net.IPMask
	mcastGroup       int
	packets          *C.packets
	quit             chan struct{}
	seq              uint32
	useMask          bool
}

// Create a new NfLog
//
// McastGroup is that specified in ip[6]tables
// IPv6 is a flag to say if it is IPv6 or not
// Direction is to monitor the source address or the dest address
func newNfLog(mcastGroup int, ipVersion byte, direction IPDirection, maskBits int, packetsToProcess, processedPackets chan []Packet) *nfLog {

	h, err := C.nflog_open()
	if h == nil || err != nil {
		log.Fatalf("Failed to open NFLOG: %s", nflogError(err))
	}
	if rc, err := C.nflog_bind_pf(h, C.AF_INET); rc < 0 || err != nil {
		log.Fatalf("nflog_bind_pf failed: %s", nflogError(err))
	}

	n := &nfLog{
		h:                h,
		fd:               C.nflog_fd(h),
		mcastGroup:       mcastGroup,
		ipVersion:        ipVersion,
		direction:        direction,
		quit:             make(chan struct{}),
		packets:          (*C.packets)(C.malloc(C.sizeof_packets)),
		packetsToProcess: packetsToProcess,
		processedPackets: processedPackets,
	}

	switch ipVersion {
	case 4:
		n.ipPacket = IP4Packet
	case 6:
		n.ipPacket = IP6Packet
	default:
		log.Fatalf("Bad IP version %d", IPVersion)
	}
	addrBits := 8 * n.ipPacket.AddrLen
	n.useMask = maskBits < addrBits
	n.mask = net.CIDRMask(maskBits, addrBits)
	n.makeGroup(mcastGroup, n.ipPacket.HeaderSize)

	return n
}

// Receive data from nflog stored in n.packets
func (n *nfLog) processPackets(addPackets []Packet) []Packet {

	np := int(n.packets.index)
	if np >= C.MAX_PACKETS {
		log.Printf("Packets buffer overflowed")
	}

	var packet []byte
	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&packet)))

	for i := 0; i < np; i++ {
		p := &n.packets.pkt[i]

		// Get the packet into a []byte
		// NB if the C data goes away then BAD things will happen!
		// So don't keep slices from this after returning from this function
		sliceHeader.Cap = int(p.payload_len)
		sliceHeader.Len = int(p.payload_len)
		sliceHeader.Data = uintptr(unsafe.Pointer(p.payload))

		// Process the packet
		newPacket := n.processPacket(packet, uint32(p.seq))
		if newPacket.Length >= 0 {
			addPackets = append(addPackets, newPacket)
		}
	}
	sliceHeader = nil
	packet = nil
	return addPackets
}

// Process a packet
func (n *nfLog) processPacket(packet []byte, seq uint32) Packet {

	// Peek the IP Version out of the header
	ipversion := packet[IPVersion] >> IPVersionShift & IPVersionMask

	if seq != 0 && seq != n.seq {
		n.errors++
		log.Printf("%d missing packets detected, %d to %d", seq-n.seq, seq, n.seq)
	}
	n.seq = seq + 1
	if ipversion != n.ipVersion {
		n.errors++
		log.Printf("Bad IP version: %d", ipversion)
		return Packet{Length: -1}
	}
	i := n.ipPacket
	if len(packet) < i.HeaderSize {
		n.errors++
		log.Printf("Short IPv%d packet %d/%d bytes", ipversion, len(packet), i.HeaderSize)
		return Packet{Length: -1}
	}

	var addr net.IP
	if n.direction {
		addr = i.Src(packet)
	} else {
		addr = i.Dst(packet)
	}

	// Mask the address
	if n.useMask {
		addr = addr.Mask(n.mask)
	}

	return Packet{
		Direction: n.direction,
		Addr:      string(addr),
		Length:    i.Length(packet),
	}
}

// Connects to the group specified with the size
func (n *nfLog) makeGroup(group, size int) {

	gh, err := C._nflog_bind_group(n.h, C.int(group))
	if gh == nil || err != nil {
		log.Fatalf("nflog_bind_group failed: %s", nflogError(err))
	}
	n.gh = gh

	// Set the maximum amount of logs in buffer for this group
	if rc, err := C.nflog_set_qthresh(gh, MaxQueueLogs); rc < 0 || err != nil {
		log.Fatalf("nflog_set_qthresh failed: %s", nflogError(err))
	}

	// Set local sequence numbering to detect missing packets
	if rc, err := C.nflog_set_flags(gh, C.NFULNL_CFG_F_SEQ); rc < 0 || err != nil {
		log.Fatalf("nflog_set_flags failed: %s", nflogError(err))
	}

	// Set buffer size large
	if rc, err := C.nflog_set_nlbufsiz(gh, NflogBufferSize); rc < 0 || err != nil {
		log.Fatalf("nflog_set_nlbufsiz: %s", nflogError(err))
	}

	// Set recv buffer large - this produces ENOBUFS when too small
	if rc, err := C.nfnl_rcvbufsiz(C.nflog_nfnlh(n.h), NfRecvBufferSize); rc < 0 || err != nil {
		log.Fatalf("nfnl_rcvbufsiz: %s", err)
	} else {
		if rc < NfRecvBufferSize {
			log.Fatalf("nfnl_rcvbufsiz: Failed to set buffer to %d got %d", NfRecvBufferSize, rc)
		}
	}

	// Set timeout
	if rc, err := C.nflog_set_timeout(gh, NflogTimeout); rc < 0 || err != nil {
		log.Fatalf("nflog_set_timeout: %s", nflogError(err))
	}

	if rc, err := C.nflog_set_mode(gh, C.NFULNL_COPY_PACKET, (C.uint)(size)); rc < 0 || err != nil {
		log.Fatalf("nflog_set_mode failed: %s", nflogError(err))
	}

	// Register the callback now we are set up
	//
	// Note that we pass a block of memory allocated by C.malloc -
	// it isn't a good idea for C to hold pointers to go objects
	// which might move
	C._callback_register(gh, n.packets)
}

// Receive packets in a loop until quit
func (n *nfLog) start() {
	buflen := C.size_t(RecvBufferSize)
	pbuf := C.malloc(buflen)
	if pbuf == nil {
		log.Fatal("No memory for malloc")
	}
	defer C.free(pbuf)

	for {
		nr, err := C.recv(n.fd, pbuf, buflen, 0)
		select {
		case <-n.quit:
			return
		default:
		}

		if nr < 0 || err != nil {
			log.Printf("Recv failed: %s", err)
			n.errors++
			continue
		}

		// Handle messages in packet reusing memory
		ps := <-n.packetsToProcess
		n.packets.index = 0
		C.nflog_handle_packet(n.h, (*C.char)(pbuf), (C.int)(nr))
		n.processedPackets <- n.processPackets(ps[:0])
	}
}

// Stop the NfLog down
func (n *nfLog) stop() {

	close(n.quit)

	if rc, err := C.nflog_close(n.h); rc < 0 || err != nil {
		log.Printf("nflog_close failed: %s", nflogError(nil))
	}

	C.free(unsafe.Pointer(n.packets))
}
