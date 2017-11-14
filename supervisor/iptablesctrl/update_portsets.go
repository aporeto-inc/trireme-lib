package iptablesctrl

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme/cache"
	"github.com/bvandewalle/go-ipset/ipset"
)

const (
	procNetTCPFile                    = "/proc/net/tcp"
	portSetUpdateIntervalMilliseconds = 500
	portEntryTimeout                  = 60
	uidFieldOffset                    = 7
	procHeaderLineNum                 = 1
	portOffset                        = 1
	ipPortOffset                      = 1
)

func getUIDPortSetMappings(i *Instance, uid string) (interface{}, error) {
	return i.UIDToPortSet.Get(uid)
}

func getUIDPortMappings(i *Instance, uid string) (interface{}, error) {
	return i.UIDToPorts.Get(uid)
}

/* This go routine is called on supervisor start */
func InitPortSetTask(i *Instance) {
	t := time.NewTicker(portSetUpdateIntervalMilliseconds * time.Millisecond)
	for range t.C {
		// Update PortSet periodically.
		updatePortSets(i)
	}
}

func updatePortSets(i *Instance) {
	file, err := os.Open(procNetTCPFile)
	if err != nil {
		zap.L().Warn("Failed To open /proc/net/tcp file", zap.Error(err))
		//log.Fatal(err)
		return
	}
	localCache := cache.NewCache("localCache")
	defer func() {
		err := file.Close()
		if err != nil {
			zap.L().Warn("Failed To close /proc/net/tcp file", zap.Error(err))
		}
	}()

	scanner := bufio.NewScanner(file)
	lineCnt := 0
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		lineCnt++
		portList := make([]int64, 0)
		if lineCnt == procHeaderLineNum {
			continue
		}
		uid := line[uidFieldOffset]
		portStr := strings.Split(line[ipPortOffset], ":")[portOffset]

		portNum, err := strconv.ParseInt(portStr, 16, 64)
		if err != nil {
			zap.L().Warn("Failed to convert port to Int", zap.Error(err))
			return
		}

		if v, err := localCache.Get(uid); err == nil {
			portList = append(v.([]int64), int64(portNum))
		} else {
			portList = append(portList, int64(portNum))
		}

		localCache.AddOrUpdate(uid, portList)

	}

	if err := scanner.Err(); err != nil {
		zap.L().Warn("Error while parsing /proc/net/tcp ", zap.Error(err))
		return

	}

	i.UIDToPorts = localCache

	// program the iptable.
	activePUs := i.UIDSet
	for k := range activePUs {
		uidPorts, err := getUIDPortMappings(i, k)
		if err != nil {
			return
		}
		puPortSetName, err := getUIDPortSetMappings(i, k)

		if err != nil {
			// Not Fatal. A normal uidlogin pu will not have a port
			return
		}

		// ipset
		ips := ipset.IPSet{
			Name: puPortSetName.(string),
		}
		// rearm the portset with new port List
		for _, port := range uidPorts.([]int64) {
			//Add an entry for 60 seconds we will rediscover ports every 60 sec
			p := strconv.Itoa(int(port))
			if adderr := ips.Add(p, portEntryTimeout); adderr != nil {
				zap.L().Warn("Failed To add port to set", zap.Error(adderr), zap.String("Setname", ips.Name))
			}
		}
	}

}
