// +build windows !linux

package portset

import (
	"errors"
	"fmt"
	"time"

	"go.aporeto.io/trireme-lib/utils/cache"
	"go.aporeto.io/trireme-lib/utils/portcache"
)

const (
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
	userPortSet          cache.DataStore
	userPortMap          cache.DataStore
	markUserMap          cache.DataStore
	contextIDFromTCPPort *portcache.PortCache
}

// expirer deletes the port entry in the portset when the key uid:port expires.
func expirer(c cache.DataStore, id interface{}, item interface{}) {
	// Empty function not implemented on non-linux platforms
	return
}

// New creates an implementation portset interface.
func New(contextIDFromTCPPort *portcache.PortCache) PortSet {

	p := &portSetInstance{
		userPortSet:          cache.NewCache("userPortSet"),
		userPortMap:          cache.NewCacheWithExpirationNotifier("userPortMap", portEntryTimeout*time.Second, expirer),
		markUserMap:          cache.NewCache("markUserMap"),
		contextIDFromTCPPort: contextIDFromTCPPort,
	}
	return p
}

// AddPortToUser adds/updates userPortMap cache. returns true if user key is already present.
func (p *portSetInstance) AddPortToUser(userName string, port string) (bool, error) {

	key := userName + ":" + port
	updated := p.userPortMap.AddOrUpdate(key, p)
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
func (p *portSetInstance) addPortSet(userName string, port string) error {
	return nil
}

func (p *portSetInstance) deletePortSet(userName string, port string) error {
	return nil
}
