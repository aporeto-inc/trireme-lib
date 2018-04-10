package ebpf

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
)

/*
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <linux/types.h>
#include <linux/bpf_common.h>

#include "ports_map.h"

static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int bpf_map_obj(char *name)
{
	union bpf_attr ports_obj = {};
	int map_fd;
	unsigned int key, value;
	char path[128];

	strncpy(path, "/sys/fs/bpf/tc/globals/", sizeof(path));
	strncat(path, name, sizeof(path) - strlen(path));

	ports_obj.map_fd = 0;
	ports_obj.pathname = (unsigned long)path;
	map_fd = bpf(BPF_OBJ_GET, &ports_obj, sizeof(ports_obj));
	if (map_fd <= 0) {
		fprintf(stderr, "Failed to Map %s\n", name);
		return -1;
	}
	return map_fd;
}

struct bpf_map_update {
	uint32_t map_fd;
	uint64_t __attribute__((aligned(8))) key;
	uint64_t __attribute__((aligned(8))) value;
	uint64_t flags;
} __attribute__((aligned(8)));

*/
import "C"

type packetKey struct {
	saddr  uint32
	daddr  uint32
	source uint16
	dest   uint16
}
type flowStats []uint64

var fd C.int
var flowCache map[packetKey]flowStats
var startTime time.Time
var flowMutex sync.Mutex

func MapCmd(fd C.int, key, value unsafe.Pointer, flags uint64, cmd uintptr) error {
	uba := C.struct_bpf_map_update{}
	uba.map_fd = C.uint32_t(fd)
	uba.key = C.uint64_t(uintptr(key))
	uba.value = C.uint64_t(uintptr(value))
	uba.flags = C.uint64_t(flags)

	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		cmd,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("unable to update element: %s", err)
	}

	return nil
}

func MapGetPortsFd(name string) C.int {
	return C.bpf_map_obj(C.CString(name))
}

func MapGetPortsKey() C.struct_ports_key {
	return C.struct_ports_key{}
}

func MapGetPortsValue() C.struct_ports_value {
	return C.struct_ports_value{}
}

func MapLookup(fd C.int, key, value unsafe.Pointer, flags uint64) error {
	return MapCmd(fd, key, value, flags, C.BPF_MAP_LOOKUP_ELEM)
}

func MapNextKey(fd C.int, key, value unsafe.Pointer, flags uint64) error {
	return MapCmd(fd, key, value, flags, C.BPF_MAP_GET_NEXT_KEY)
}

func MapDelete(fd C.int, key, value unsafe.Pointer, flags uint64) error {
	return MapCmd(fd, key, value, flags, C.BPF_MAP_DELETE_ELEM)
}

func MapUpdate(fd C.int, key, value unsafe.Pointer, flags uint64) error {
	return MapCmd(fd, key, value, flags, C.BPF_MAP_UPDATE_ELEM)
}

func printFlowStats(packet *packetKey, bytes uint64) {
	fmt.Println("source = ", packet.saddr, " dest = ", packet.daddr,
		" sport = ", packet.source, " dport = ", packet.dest, " bytes = ", bytes)

}

func updateBpfMapInternal(packet *packetKey) {
	key := MapGetPortsKey()
	value := MapGetPortsValue()

	key.saddr = C.uint32_t(packet.saddr)
	key.daddr = C.uint32_t(packet.daddr)
	key.source = C.uint16_t(packet.source)
	key.dest = C.uint16_t(packet.dest)
	value.bytes = 0
	value.fin = 0

	flowMutex.Lock()
	defer flowMutex.Unlock()

	if time.Since(startTime) > (time.Minute * 2) {
		for k, v := range flowCache {
			for _, val := range v {
				printFlowStats(&k, val)
			}
		}

		for MapNextKey(fd, unsafe.Pointer(&key), unsafe.Pointer(&key), 0) == nil {
			MapLookup(fd, unsafe.Pointer(&key), unsafe.Pointer(&value), 0)

			goPacket := packetKey{
				saddr:  uint32(key.saddr),
				daddr:  uint32(key.daddr),
				source: uint16(key.source),
				dest:   uint16(key.dest),
			}

			printFlowStats(&goPacket, uint64(value.bytes))

			if value.fin == 1 {
				MapDelete(fd, unsafe.Pointer(&key), unsafe.Pointer(&value), 0)
			}
		}
		startTime = time.Now()
	}

	if _, ok := flowCache[*packet]; ok {
		MapLookup(fd, unsafe.Pointer(&key), unsafe.Pointer(&value), 0)
		flowCache[*packet] = append(flowCache[*packet], uint64(value.bytes))
	} else {
		flowCache[*packet] = flowStats{}
	}

	value.bytes = 0
	value.fin = 0
	MapUpdate(fd, unsafe.Pointer(&key), unsafe.Pointer(&value), C.BPF_ANY)
}

func UpdateBpfMap(tcpPacket *packet.Packet) {

	zap.L().Error("Updating ebpf map",
		zap.String("flow", tcpPacket.L4FlowHash()))

	packet := packetKey{
		saddr:  binary.BigEndian.Uint32(tcpPacket.SourceAddress),
		daddr:  binary.BigEndian.Uint32(tcpPacket.DestinationAddress),
		source: tcpPacket.SourcePort,
		dest:   tcpPacket.DestinationPort,
	}

	go updateBpfMapInternal(&packet)
}

func executeCommand(cmd string) {
	cmdSplit := strings.Split(cmd, " ")

	out, err := exec.Command(cmdSplit[0], cmdSplit[1:]...).Output()

	if err != nil {
		zap.L().Error("tc command failed",
			zap.String("command", cmd),
			zap.String("error", string(out)))
	}
}

func loadBpfCode() {
	executeCommand("./tc qdisc add dev lo ingress handle ffff:")
	executeCommand("./tc filter add dev lo parent ffff: bpf obj filter_in.o action ok classid 1")
	executeCommand("./tc filter add dev lo parent ffff: bpf obj filter_in_main.o action ok classid 1")
	executeCommand("./tc qdisc add dev lo root handle 1: htb")
	executeCommand("./tc filter add dev lo parent 1: bpf obj filter_in.o")
	executeCommand("./tc filter add dev lo parent 1: bpf obj filter_out.o")
}

func init() {
	zap.L().Error("Initializing BPF map")

	startTime = time.Now()
	flowCache = make(map[packetKey]flowStats)
	loadBpfCode()
	fd = MapGetPortsFd("in_ports")
}

/*

// Test code. Arguments are sip dip sport dport to add to the map.
func main() {

	args := os.Args
	fd := MapGetPortsFd("in_ports")

	key := MapGetPortsKey()
	value := MapGetPortsValue()
	key.saddr = inet_atoh(args[1])
	key.daddr = inet_atoh(args[2])
	s, _ := strconv.Atoi(args[3])
	d, _ := strconv.Atoi(args[4])
	key.source = C.uint16_t(s)
	key.dest = C.uint16_t(d)
	value.bytes = 0
	value.fin = 0

	fmt.Printf("DEBUG adding sourceip=%x destip=%x sourceport=%d destport=%d\n",
		uint(key.saddr),
		uint(key.daddr),
		uint(key.source),
		uint(key.dest))

	MapUpdate(fd, unsafe.Pointer(&key), unsafe.Pointer(&value), C.BPF_NOEXIST)

	// Sleep to give a chance to ebpf to capture some traffic
	time.Sleep(10 * time.Second)

	// Print the content of the whole map
	key.saddr = 0
	key.daddr = 0
	key.source = 0
	key.dest = 0
	value.bytes = 0
	for MapNextKey(fd, unsafe.Pointer(&key), unsafe.Pointer(&key), 0) == nil {
		MapLookup(fd, unsafe.Pointer(&key), unsafe.Pointer(&value), 0)

		fmt.Printf("DEBUG sourceip=%s destip=%s sourceport=%d destport=%d bytes=%d fin=%d\n", inet_htoa(key.saddr), inet_htoa(key.daddr),
			uint(key.source),
			uint(key.dest),
			uint(value.bytes),
			uint(value.fin))
	}
}
*/
