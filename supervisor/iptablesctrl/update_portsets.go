package iptablesctrl

import (
	"bufio"
	"fmt"
	"log"
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
)

func getUIDPortSetMappings(i *Instance, uid string) (interface{}, error) {
	return i.UIDToPortSet.Get(uid)
}

func getUIDPortMappings(i *Instance, uid string) (interface{}, error) {
	return i.UIDToPorts.Get(uid)
}

func InitPortSetTask(i *Instance) {
	t := time.NewTicker(portSetUpdateIntervalMilliseconds * time.Millisecond)
	for range t.C {
		// Update PortSet periodically.
		updatePortSets(i)
	}
}

// TODO : Handle file handling errors, use zap to log
func updatePortSets(i *Instance) {
	file, err := os.Open(procNetTCPFile)
	localCache := cache.NewCache("localCache")
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCnt := 0
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		lineCnt++
		portList := make([]int64, 0)
		if lineCnt == 1 {
			continue
		}
		uid := line[7]
		portStr := strings.Split(line[1], ":")[1]

		portNum, err := strconv.ParseInt(portStr, 16, 64)
		if err != nil {
			log.Fatal(err)
		}

		if v, err := localCache.Get(uid); err == nil {
			portList = append(v.([]int64), int64(portNum))
		} else {
			portList = append(portList, int64(portNum))
		}

		localCache.AddOrUpdate(uid, portList)

	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	i.UIDToPorts = localCache

	// program the iptable.
	activePUs := i.UIDSet
	for k, _ := range activePUs {
		zap.L().Debug("Programming the port set for - Varun")
		fmt.Println("UID ", k)
		uidPorts, err := getUIDPortMappings(i, k)
		if err != nil {
			return
		}
		puPortSetName, err := getUIDPortSetMappings(i, k)

		if err != nil {
			zap.L().Warn("Failed To get UID to portset mappings", zap.String("UID:", k))
			// Fatal ?
			return
		}

		// ipset
		ips := ipset.IPSet{
			Name: puPortSetName.(string),
		}
		// Before we rearm with new PortSet, Do we need to clear the current portset ?

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
