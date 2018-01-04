package portset

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/aporeto-inc/trireme-lib/utils/cache"
	"github.com/aporeto-inc/trireme-lib/utils/portcache"
	"github.com/bvandewalle/go-ipset/ipset"
	"go.uber.org/zap"
)

const (
	procNetTCPFile                 = "/proc/net/tcp"
	portSetUpdateIntervalinSeconds = 2
	portEntryTimeout               = 5 * portSetUpdateIntervalinSeconds
	uidFieldOffset                 = 7
	procHeaderLineNum              = 0
	portOffset                     = 1
	ipPortOffset                   = 1
	sockStateOffset                = 3
	sockListeningState             = "0A"
	hexFormat                      = 16
	integerSize                    = 64
	minimumFields                  = 2
)

// portSetInstance contains look up tables to manage updates to ipset portsets.
type portSetInstance struct {
	userPortSet       cache.DataStore
	userPortMap       cache.DataStore
	markUserMap       cache.DataStore
	contextIDFromPort *portcache.PortCache
}

// expirer deletes the port entry in the portset when the key uid:port expires.
func expirer(c cache.DataStore, id interface{}, item interface{}) {

	userPort := strings.Split(id.(string), ":")
	portSetObject := item.(*portSetInstance)

	if len(userPort) < minimumFields {
		zap.L().Debug("Failed to remove key from the cache")
		return
	}

	if portSetObject == nil {
		zap.L().Debug("Invalid portSetObject")
		return
	}

	user := userPort[0]
	port := userPort[1]

	if err := portSetObject.deletePortSet(user, port); err != nil {
		zap.L().Debug("Cache: Failed to delete port from set", zap.Error(err))
	}

	// delete the port from contextIDFromPort cache
	if err := portSetObject.contextIDFromPort.RemoveStringPorts(port); err != nil {
		zap.L().Debug("Unable to remove port from contextIDFromPort Cache")
	}

}

// New creates an implementation portset interface.
func New(contextIDFromPort *portcache.PortCache) PortSet {

	p := &portSetInstance{
		userPortSet:       cache.NewCache("userPortSet"),
		userPortMap:       cache.NewCacheWithExpirationNotifier("userPortMap", portEntryTimeout*time.Second, expirer),
		markUserMap:       cache.NewCache("markUserMap"),
		contextIDFromPort: contextIDFromPort,
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

// AddPortToUser adds/updates userPortMap cache. returns true if user key is already present.
func (p *portSetInstance) AddPortToUser(userName string, port string) (bool, error) {

	key := userName + ":" + port
	updated := p.userPortMap.AddOrUpdate(key, p)

	// program the ipset
	if err := p.addPortSet(userName, port); err != nil {
		return false, err
	}
	return updated, nil
}

// AddUserPortSet adds/updates userPortSet/markUserMap cache. userPortSet cache
// maps user to the portset associated with its PU. markUserMap maps the packet mark
// the userName. This gets called during the creation of PU/on reception of application SYN-ACK packet.
func (p *portSetInstance) AddUserPortSet(userName string, portset string, mark string) (err error) {

	p.userPortSet.AddOrUpdate(userName, portset)
	p.markUserMap.AddOrUpdate(mark, userName)
	return nil

}

// getUserPortSet returns the portset associated with user.
func (p *portSetInstance) getUserPortSet(userName string) (string, error) {

	portSetName, err := p.userPortSet.Get(userName)
	if err != nil {
		return "", fmt.Errorf("invalid portset name: %s", err)
	}

	port, ok := portSetName.(string)
	if !ok {
		return "", errors.New("invalid portset name: portset name is not a string")
	}

	return port, nil
}

// DelUserPortSet deletes user and mark entries from caches.
func (p *portSetInstance) DelUserPortSet(userName string, mark string) (err error) {

	if err = p.userPortSet.Remove(userName); err != nil {
		return fmt.Errorf("unable to remove uid from portset cache: %s", err)
	}

	return p.markUserMap.Remove(mark)
}

// GetuserMark return username associated with packet mark.
func (p *portSetInstance) GetUserMark(mark string) (string, error) {

	userName, err := p.markUserMap.Get(mark)
	if err != nil {
		return "", fmt.Errorf("invalid mark: %s", err)
	}

	user, ok := userName.(string)
	if !ok {
		return "", errors.New("invalid mark: not a string")
	}

	return user, nil
}

// addPortSet programs the ipset portset with port. The portset name is derived from userPortSet cache.
func (p *portSetInstance) addPortSet(userName string, port string) (err error) {

	puPortSetName, err := p.getUserPortSet(userName)
	if err != nil {
		return fmt.Errorf("unable to get portset from uid: %s", err)
	}

	ips := ipset.IPSet{
		Name: puPortSetName,
	}

	if _, err = strconv.Atoi(port); err != nil {
		return fmt.Errorf("invalid port: %s", err)
	}

	if err = ips.Add(port, 0); err != nil {
		return fmt.Errorf("unable to add port to set: %s", err)
	}

	return nil
}

// deletePortSet deletes the portset.
func (p *portSetInstance) deletePortSet(userName string, port string) error {

	puPortSetName, err := p.getUserPortSet(userName)
	if err != nil {
		return fmt.Errorf("unable to get portset from uid: %s", err)
	}

	ips := ipset.IPSet{
		Name: puPortSetName,
	}

	if _, err = strconv.Atoi(port); err != nil {
		return fmt.Errorf("invalid port: %s", err)
	}

	if err = ips.Del(port); err != nil {
		return fmt.Errorf("unable to delete port from portset: %s", err)
	}

	return nil
}

// startPortSetTask is a go routine that periodically scans /proc/net/tcp file
// for listening ports and programs the portsets. This worker thread is setup
// during datapath initilisation.
func startPortSetTask(p *portSetInstance) {

	t := time.NewTicker(portSetUpdateIntervalinSeconds * time.Second)
	for range t.C {
		// Update PortSet periodically.
		p.updateIPPortSets()
	}
}

func (p *portSetInstance) updateIPPortSets() {

	buffer, err := ioutil.ReadFile(procNetTCPFile)
	if err != nil {
		zap.L().Debug("Failed to read /proc/net/tcp file", zap.Error(err))
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
			zap.L().Debug("Failed to extract port")
			continue
		}

		port := ipPort[portOffset]
		// convert the hex port to int
		portNum, err := strconv.ParseInt(port, hexFormat, integerSize)
		if err != nil {
			zap.L().Debug("Failed to convert port to Int", zap.Error(err))
			continue
		}

		// /proc/net/tcp file contains uid. Conversion to
		// userName is required as they are keys to lookup tables.
		userName, err := getUserName(uid)
		if err != nil {
			zap.L().Debug("Error converting to username", zap.Error(err))
			continue
		}

		port = strconv.Itoa(int(portNum))
		portKey := userName + ":" + port

		// check if username corresponds to a valid uidloginpu
		if _, err = p.userPortSet.Get(userName); err != nil {
			continue
		}

		if updated := p.userPortMap.AddOrUpdate(portKey, p); updated {
			continue
		}

		if err = p.addPortSet(userName, port); err != nil {
			zap.L().Debug("Unable to add port to portset ", zap.Error(err))
		}
	}
}
