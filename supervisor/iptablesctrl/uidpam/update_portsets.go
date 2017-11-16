package uipam

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/aporeto-inc/trireme-lib/cache"
	"github.com/bvandewalle/go-ipset/ipset"
	"go.uber.org/zap"
)

const (
	procNetTCPFile                    = "/proc/net/tcp"
	portSetUpdateIntervalMilliseconds = 1000
	portEntryTimeout                  = 60
	uidFieldOffset                    = 7
	procHeaderLineNum                 = 1
	portOffset                        = 1
	ipPortOffset                      = 1
	sockStateOffset                   = 3
	sockListeningState                = "0A"
	hexFormat                         = 16
	integerSize                       = 64
	decFormat                         = 10
)

// PortSet : This provides an interface to update the
// look up table required to program the ipset portsets.
type PortSet interface {
	AddToUIDToPortSetCache(uid string, value string) (err error)
	GetFromUIDToPortSetCache(uid string) (err error)
	AddToUIDToPortsCache(uid string, value string) (ok bool)
	RemoveFromUIDToPortSetCache(uid string) (err error)
	RemoveFromUIDToPortsCache(uid string) (err error)
	UpdatePortSet(uid string, port string)
}

// UIDCacheInstance : This type contains look up tables
// to help update the ipset portsets.
type UIDCacheInstance struct {
	UIDToPortSet *cache.Cache
	UIDToPorts   *cache.Cache
	UIDSet       map[string]bool
}

// NewInstance : creates a new UIDCache instance
func NewInstance() (p *UIDCacheInstance, err error) {

	p = &UIDCacheInstance{
		UIDToPortSet: cache.NewCache("UIDToPortSet"),
		UIDToPorts:   cache.NewCache("UIDToPorts"),
		UIDSet:       make(map[string]bool), // updated on portset create/delete
	}

	return p, nil
}

func (p *UIDCacheInstance) getUserID(username string) (string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", err
	}
	return u.Uid, nil
}

// AddToUIDToPortsCache This adds/updates UIDToPorts cache. This cache
// maps UID to list of active listening ports.
func (p *UIDCacheInstance) AddToUIDToPortsCache(username string, portStr string) (ok bool, err error) {
	ok = false
	portList := make([]int64, 0)
	portNum, err := strconv.ParseInt(portStr, decFormat, integerSize)

	if err != nil {
		return ok, err
	}

	uid, err := p.getUserID(username)
	if err != nil {
		return ok, err
	}

	if v, err := p.UIDToPortSet.Get(uid); err == nil {
		portList = append(v.([]int64), portNum)
		p.UIDToPorts.AddOrUpdate(uid, portList)
		ok = true
	} else {
		portList = append(portList, portNum)
		p.UIDToPorts.Add(uid, portList)
	}

	return ok, nil
}

// AddToUIDToPortSetCache : This adds/updates UIDToPortSet cache. This cache
// maps UID to the portset associated with its PU. This is called during
// creation of PU/on reception of application SYN-ACK packet.
func (p *UIDCacheInstance) AddToUIDToPortSetCache(username string, portset string) (err error) {
	uid, err := p.getUserID(username)
	if err != nil {
		return err
	}

	p.UIDToPortSet.AddOrUpdate(uid, portset)
	p.UIDSet[uid] = true
	return nil

}

// GetFromUIDToPortSetCache : This returns the portset associated with UID.
func (p *UIDCacheInstance) GetFromUIDToPortSetCache(username string) (port string, err error) {
	uid, err := p.getUserID(username)
	if err != nil {
		return "", err
	}
	portSetName, err := p.UIDToPortSet.Get(uid)
	if err != nil {
		return "", err
	}
	return portSetName.(string), nil
}

// RemoveFromUIDToPortSetCache : This deletes UID from UIDToPortSet cache. This is called
// during removal of PU.
func (p *UIDCacheInstance) RemoveFromUIDToPortSetCache(username string) (err error) {
	uid, err := p.getUserID(username)
	if err != nil {
		return err
	}
	delete(p.UIDSet, uid)
	return p.UIDToPortSet.Remove(uid)
}

// RemoveFromUIDToPortsCache : Is this ever required ? Go routine updates the Port
func (p *UIDCacheInstance) RemoveFromUIDToPortsCache(uid string) (err error) {
	return nil
}

// UpdatePortSet : This API programs the ipset portset with port. The
// portset name is derived from UIDToPortSet cache.
func (p *UIDCacheInstance) UpdatePortSet(username string, port string) (err error) {

	puPortSetName, err := p.GetFromUIDToPortSetCache(username)
	if err != nil {
		return fmt.Errorf("Unable to get portset from uid")
	}

	ips := ipset.IPSet{
		Name: puPortSetName,
	}

	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("Not a valid Port")
	}

	if adderr := ips.Add(port, portEntryTimeout); adderr != nil {
		return fmt.Errorf("Unable to add port to set")
	}
	return nil
}

// InitPortSetTask This go routine periodically scans (1s)
// /proc/net/tcp file for listening ports and programs
// the portsets. This worker thread is setup during datapath
// initilisation.
func InitPortSetTask(p *UIDCacheInstance) {
	go startPortSetTask(p)
}

func startPortSetTask(p *UIDCacheInstance) {
	t := time.NewTicker(portSetUpdateIntervalMilliseconds * time.Millisecond)
	for range t.C {
		// Update PortSet periodically.
		p.updateIPPortSets()
	}
}

func (p *UIDCacheInstance) updateIPPortSets() {
	file, err := os.Open(procNetTCPFile)
	if err != nil {
		zap.L().Warn("Failed To open /proc/net/tcp file", zap.Error(err))
		return
	}
	defer func() {
		err := file.Close()
		if err != nil {
			zap.L().Warn("Failed To close /proc/net/tcp file", zap.Error(err))
		}
	}()

	localCache := cache.NewCache("localCache")
	scanner := bufio.NewScanner(file)
	lineCnt := 0
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		lineCnt++
		portList := make([]int64, 0)
		if (lineCnt == procHeaderLineNum) || (line[sockStateOffset] != sockListeningState) {
			continue
		}
		uid := line[uidFieldOffset]
		portStr := strings.Split(line[ipPortOffset], ":")[portOffset]

		portNum, err := strconv.ParseInt(portStr, hexFormat, integerSize)
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

	p.UIDToPorts = localCache

	// program the iptable.
	activePUs := p.UIDSet
	for k := range activePUs {
		uidPorts, err := p.UIDToPorts.Get(k) //getUIDPortMappings(k)
		if err != nil {
			continue
		}
		puPortSetName, err := p.UIDToPortSet.Get(k) //getUIDPortSetMappings(k)

		if err != nil {
			// Not Fatal. A normal uidlogin pu will not have a port
			continue
		}

		// ipset
		ips := ipset.IPSet{
			Name: puPortSetName.(string),
		}
		// rearm the portset with new port List
		for _, port := range uidPorts.([]int64) {
			//Add an entry for 60 seconds we will rediscover ports every 60 sec
			portNum := strconv.Itoa(int(port))
			if adderr := ips.Add(portNum, portEntryTimeout); adderr != nil {
				zap.L().Warn("Failed To add port to set", zap.Error(adderr), zap.String("Setname", ips.Name))
			}
		}
	}

}
