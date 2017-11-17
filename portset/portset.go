package portset

import (
	"fmt"
	"io/ioutil"
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
	portEntryTimeout                  = portSetUpdateIntervalMilliseconds * 3
	uidFieldOffset                    = 7
	procHeaderLineNum                 = 0
	portOffset                        = 1
	ipPortOffset                      = 1
	sockStateOffset                   = 3
	sockListeningState                = "0A"
	hexFormat                         = 16
	integerSize                       = 64
	minimumFields                     = 2
)

// portSetInstance : This type contains look up tables
// to help update the ipset portsets.
type portSetInstance struct {
	userPortSet *cache.Cache
	userPortMap *cache.Cache
}

// deletes the port entry in the portset when the key uid:port
// expires
func expirer(c cache.DataStore, id interface{}, item interface{}) {

	userPort := strings.Split(id.(string), ":")
	portSetObject := item.(*portSetInstance)

	if len(userPort) < minimumFields {
		zap.L().Warn("Failed to remove key from the cache")
	}

	user := userPort[0]
	port := userPort[1]

	if err := portSetObject.deletePortSet(user, port); err != nil {
		zap.L().Warn("Failed to delete port from set", zap.Error(err))
	}

}

// New creates a portset interface
func New() PortSet {

	p := &portSetInstance{
		userPortSet: cache.NewCache("userPortSet"),
		userPortMap: cache.NewCacheWithExpirationNotifier("userPortMap", portEntryTimeout, expirer),
	}

	go startPortSetTask(p)

	return p
}

func getUserName(uid string) (string, error) {

	u, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// AddPortToUser adds/updates userPortMap cache. returns
// true if user key is already present
func (p *portSetInstance) AddPortToUser(userName string, port string) (bool, error) {

	key := userName + ":" + port
	updated := p.userPortMap.AddOrUpdate(key, p)

	// program the ipset
	if err := p.addPortSet(userName, port); err != nil {
		return false, err
	}
	return updated, nil
}

// AddUserPortSet : This adds/updates userPortSet cache. This cache
// maps user to the portset associated with its PU. This is called during
// creation of PU/on reception of application SYN-ACK packet.
func (p *portSetInstance) AddUserPortSet(userName string, portset string) (err error) {

	p.userPortSet.AddOrUpdate(userName, portset)
	return nil

}

// GetUserPortSet returns the portset associated with user.
func (p *portSetInstance) getUserPortSet(userName string) (port string, err error) {

	if portSetName, err := p.userPortSet.Get(userName); err == nil {
		if port, ok := portSetName.(string); ok {
			return port, nil
		}
		err = fmt.Errorf("Invalid portset name")
	}
	return "", err
}

// DelUserPortSet  deletes user from userPortSet cache.
func (p *portSetInstance) DelUserPortSet(userName string) (err error) {

	return p.userPortSet.Remove(userName)
}

// addPortSet  programs the ipset portset with port. The
// portset name is derived from userPortSet cache.
func (p *portSetInstance) addPortSet(userName string, port string) (err error) {

	puPortSetName, err := p.getUserPortSet(userName)
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

// deletePortSet deletes the portset
func (p *portSetInstance) deletePortSet(userName string, port string) (err error) {

	puPortSetName, err := p.getUserPortSet(userName)
	if err != nil {
		return fmt.Errorf("Unable to get portset from uid")
	}

	ips := ipset.IPSet{
		Name: puPortSetName,
	}

	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("Not a valid Port")
	}

	if delerr := ips.Del(port); delerr != nil {
		return fmt.Errorf("Unable to delete port from portset")
	}

	return nil
}

// startPortSetTask This go routine periodically scans (1s)
// /proc/net/tcp file for listening ports and programs
// the portsets. This worker thread is setup during datapath
// initilisation.
func startPortSetTask(p *portSetInstance) {

	t := time.NewTicker(portSetUpdateIntervalMilliseconds * time.Millisecond)
	for range t.C {
		// Update PortSet periodically.
		p.updateIPPortSets()
	}
}

func (p *portSetInstance) updateIPPortSets() {

	buffer, err := ioutil.ReadFile(procNetTCPFile)
	if err != nil {
		zap.L().Warn("Failed to read /proc/net/tcp file", zap.Error(err))
		// This is a go routine, cannot return error
		return
	}

	s := string(buffer)

	for cnt, line := range strings.Split(s, "\n") {

		line := strings.Fields(line)
		// continue if not a valid line
		if len(line) < uidFieldOffset {
			continue
		}

		if (cnt == procHeaderLineNum) || (line[sockStateOffset] != sockListeningState) {
			continue
		}

		uid := line[uidFieldOffset]
		ipPort := strings.Split(line[ipPortOffset], ":")

		if len(ipPort) < minimumFields {
			zap.L().Warn("Failed to convert port to Int")
			continue
		}

		port := ipPort[portOffset]
		// conver the hex port to int
		portNum, err := strconv.ParseInt(port, hexFormat, integerSize)
		if err != nil {
			zap.L().Warn("Failed to convert port to Int", zap.Error(err))
			continue
		}

		portKey := uid + ":" + strconv.Itoa(int(portNum))
		if updated := p.userPortMap.AddOrUpdate(portKey, p); updated {
			continue
		}

		// /proc/net/tcp file contains uid. Conversion to
		// userName is required as they are keys to lookup tables.
		userName, err := getUserName(uid)
		if err != nil {
			zap.L().Warn("Error converting to username", zap.Error(err))
			continue
		}

		if err = p.addPortSet(userName, port); err != nil {
			zap.L().Warn("Unable to add port to portset ", zap.Error(err))
		}
	}
}
