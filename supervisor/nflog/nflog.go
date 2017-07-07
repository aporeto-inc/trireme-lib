// +build linux !darwin

// Use cgo to interface with nflog
//
// Docs: http://www.netfilter.org/projects/libnetfilter_log/doxygen/index.html
//
// Debian packages needed:
//   apt-get install iptables-dev linux-libc-dev libnetfilter-log-dev

package nflog

import (
	"fmt"
	"net"
	"reflect"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
)

/*
#cgo LDFLAGS: -lnfnetlink -lnetfilter_log
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <inttypes.h>

// A record of each packet
typedef struct {
	char *payload;
	int payload_len;
	u_int32_t seq;
    char *prefix;
    int prefix_len;
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
    p->prefix = 0;
    p->prefix = nflog_get_prefix(nfd);
    p->prefix_len = strlen(p->prefix);
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
	recvBufferSize   = 4 * 1024 * 1024
	nflogBufferSize  = 128 * 1024 // Must be <= 128k (checked in kernel source)
	nfrecvBufferSize = 16 * 1024 * 1024
	nflogTimeout     = 100 // Timeout before sending data in 1/100th second
	maxQueueLogs     = C.MAX_PACKETS - 1
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
	quit             chan struct{}
	direction        IPDirection
	ipVersion        byte
	useMask          bool
	mask             net.IPMask
	gh               *C.struct_nflog_g_handle
	h                *C.struct_nflog_handle
	ipPacket         *IPPacketInfo
	packets          *C.packets
	mcastGroup       int
	seq              uint32
	fd               C.int
	errors           int64
}

// Create a new NfLog
//
// McastGroup is that specified in ip[6]tables
// IPv6 is a flag to say if it is IPv6 or not
// Direction is to monitor the source address or the dest address
func newNfLog(mcastGroup int, ipVersion byte, direction IPDirection, maskBits int, packetsToProcess, processedPackets chan []Packet) (*nfLog, error) {

	h, err := C.nflog_open()
	if h == nil || err != nil {
		return nil, fmt.Errorf("Failed to open NFLOG: %s", nflogError(err))
	}
	if rc, err := C.nflog_bind_pf(h, C.AF_INET); rc < 0 || err != nil {
		return nil, fmt.Errorf("nflog_bind_pf failed: %s", nflogError(err))
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
		return nil, fmt.Errorf("nflog: bad IP version %d", IPVersion)
	}
	addrBits := 8 * n.ipPacket.AddrLen
	n.useMask = maskBits < addrBits
	n.mask = net.CIDRMask(maskBits, addrBits)

	if err := n.makeGroup(mcastGroup, n.ipPacket.HeaderSize); err != nil {
		return nil, err
	}

	return n, nil
}

// Receive data from nflog stored in n.packets
func (n *nfLog) processPackets(addPackets []Packet) []Packet {

	np := int(n.packets.index) // nolint: gotype
	if np >= C.MAX_PACKETS {
		zap.L().Warn("nflog: packets buffer overflowed")
	}

	var payload []byte
	payloadSliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&payload))) // nolint: gotype

	var prefix []byte
	prefixSliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&prefix))) // nolint: gotype

	for i := 0; i < np; i++ {
		p := &n.packets.pkt[i] // nolint: gotype

		// Get the packet into a []byte
		// NB if the C data goes away then BAD things will happen!
		// So don't keep slices from this after returning from this function
		payloadSliceHeader.Cap = int(p.payload_len)
		payloadSliceHeader.Len = int(p.payload_len)
		payloadSliceHeader.Data = uintptr(unsafe.Pointer(p.payload))

		prefixSliceHeader.Cap = int(p.prefix_len)
		prefixSliceHeader.Len = int(p.prefix_len)
		prefixSliceHeader.Data = uintptr(unsafe.Pointer(p.prefix))

		// Process the packet
		newPacket := n.processPacket(payload, prefix, uint32(p.seq))
		if newPacket.Length >= 0 {
			addPackets = append(addPackets, newPacket)
		}
	}
	payloadSliceHeader = nil
	prefixSliceHeader = nil
	payload = nil
	return addPackets
}

// Process a packet
func (n *nfLog) processPacket(payload []byte, prefix []byte, seq uint32) Packet {

	// Peek the IP Version out of the header
	ipversion := payload[IPVersion] >> IPVersionShift & IPVersionMask

	if seq != 0 && seq != n.seq {
		n.errors++
		zap.L().Warn("nflog: missing packets detected", zap.Uint32("missing", seq-n.seq), zap.Uint32("current", seq), zap.Uint32("previous", n.seq))
	}
	n.seq = seq + 1
	if ipversion != n.ipVersion {
		n.errors++
		return Packet{Length: -1}
	}
	i := n.ipPacket
	if len(payload) < i.HeaderSize {
		n.errors++
		return Packet{Length: -1}
	}

	var addr net.IP
	if n.direction {
		addr = i.Src(payload)
	} else {
		addr = i.Dst(payload)
	}

	// Mask the address
	if n.useMask {
		addr = addr.Mask(n.mask)
	}

	return Packet{
		Prefix:    string(prefix),
		Direction: n.direction,
		Addr:      string(addr),
		Length:    i.Length(payload),
	}
}

// Connects to the group specified with the size
func (n *nfLog) makeGroup(group, size int) error {

	gh, err := C._nflog_bind_group(n.h, C.int(group))
	if gh == nil || err != nil {
		return fmt.Errorf("nflog: nflog_bind_group failed: %s", nflogError(err))
	}
	n.gh = gh

	var rc C.int
	var urc C.uint

	// Set the maximum amount of logs in buffer for this group
	if rc, err = C.nflog_set_qthresh(gh, maxQueueLogs); rc < 0 || err != nil {
		return fmt.Errorf("nflog: nflog_set_qthresh failed: %s", nflogError(err))
	}

	// Set local sequence numbering to detect missing packets
	if rc, err = C.nflog_set_flags(gh, C.NFULNL_CFG_F_SEQ); rc < 0 || err != nil {
		return fmt.Errorf("nflog: nflog_set_flags failed: %s", nflogError(err))
	}

	// Set buffer size large
	if rc, err = C.nflog_set_nlbufsiz(gh, nflogBufferSize); rc < 0 || err != nil {
		return fmt.Errorf("nflog: nflog_set_nlbufsiz failed: %s", nflogError(err))
	}

	// Set recv buffer large - this produces ENOBUFS when too small
	urc, err = C.nfnl_rcvbufsiz(C.nflog_nfnlh(n.h), nfrecvBufferSize)
	if err != nil {
		return fmt.Errorf("nflog: nfnl_rcvbufsiz failed: %s", nflogError(err))
	}
	if urc < nfrecvBufferSize {
		return fmt.Errorf("nflog: nfnl_rcvbufsiz: Failed to set buffer to %d got %d", nfrecvBufferSize, urc)
	}

	// Set timeout
	if rc, err = C.nflog_set_timeout(gh, nflogTimeout); rc < 0 || err != nil {
		return fmt.Errorf("nflog: nflog_set_timeout failed: %s", nflogError(err))
	}

	if rc, err = C.nflog_set_mode(gh, C.NFULNL_COPY_PACKET, (C.uint)(size)); rc < 0 || err != nil {
		return fmt.Errorf("nflog: nflog_set_mode failed: %s", nflogError(err))
	}

	// Register the callback now we are set up
	//
	// Note that we pass a block of memory allocated by C.malloc -
	// it isn't a good idea for C to hold pointers to go objects
	// which might move
	C._callback_register(gh, n.packets)

	return nil
}

// Receive packets in a loop until quit
func (n *nfLog) start() {
	buflen := C.size_t(recvBufferSize)
	pbuf := C.malloc(buflen)
	if pbuf == nil {
		panic("nflog: no memory for malloc")
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
			zap.L().Warn("nflog: recv failed %s", zap.Error(err))
			n.errors++
			continue
		}

		// Handle messages in packet reusing memory
		ps := <-n.packetsToProcess
		n.packets.index = 0 // nolint: gotype
		C.nflog_handle_packet(n.h, (*C.char)(pbuf), (C.int)(nr))
		n.processedPackets <- n.processPackets(ps[:0])
	}
}

// Stop the NfLog down
func (n *nfLog) stop() {

	close(n.quit)

	if rc, err := C.nflog_close(n.h); rc < 0 || err != nil {
		zap.L().Warn("nflog: nflog_close failed %s", zap.Error(nflogError(err)))
	}

	C.free(unsafe.Pointer(n.packets))
}
