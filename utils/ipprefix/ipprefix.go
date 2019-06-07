package ipprefix

import (
	"encoding/binary"
	"net"
	"sync"
)

// FuncOnLpmIP is the type of func which will operate on the value associated with the lpm ip.
type FuncOnLpmIP func(val interface{}) bool

// FuncOnVals is the type of the func which will operate on each value and will return a new value
// for each associated value.
type FuncOnVals func(val interface{}) interface{}

//IPcache is an interface which provides functionality to store ip's and do longest prefix match
type IPcache interface {
	// Put takes an argument an ip address, mask and value.
	Put(net.IP, int, interface{})
	// Get takes an argument the IP address and mask and returns the value that is stored for
	// that key.
	Get(net.IP, int) (interface{}, bool)
	// RunFuncOnLpmIP function takes as an argument an IP address and a function. It finds the
	// subnet to which this IP belongs with the longest prefix match. It then calls the
	// function supplied by the user on the value stored and if it succeeds then it returns.
	RunFuncOnLpmIP(net.IP, FuncOnLpmIP)
	// RunFuncOnVals takes an argument a function which is called on all the values stored in
	// the cache. This can be used to update the old values with the new values. If the new
	// value is nil, it will delete the key.
	RunFuncOnVals(FuncOnVals)
}

const (
	ipv4MaskSize = 32 + 1
	ipv6MaskSize = 128 + 1
)

type ipcacheV4 struct {
	ipv4 []map[uint32]interface{}
	sync.RWMutex
}

type ipcacheV6 struct {
	ipv6 []map[[16]byte]interface{}
	sync.RWMutex
}

type ipcache struct {
	ipv4 *ipcacheV4
	ipv6 *ipcacheV6
}

func (cache *ipcacheV4) Put(ip net.IP, mask int, val interface{}) {
	cache.Lock()
	defer cache.Unlock()

	if cache.ipv4[mask] == nil {
		cache.ipv4[mask] = map[uint32]interface{}{}
	}

	m := cache.ipv4[mask]
	// the following expression is ANDing the ip with the mask
	m[binary.BigEndian.Uint32(ip)&binary.BigEndian.Uint32(net.CIDRMask(mask, 32))] = val
}

func (cache *ipcacheV4) Get(ip net.IP, mask int) (interface{}, bool) {
	cache.RLock()
	defer cache.RUnlock()

	m := cache.ipv4[mask]
	if m != nil {
		val, ok := m[binary.BigEndian.Uint32(ip)&binary.BigEndian.Uint32(net.CIDRMask(mask, 32))]
		if ok {
			return val, true
		}
	}

	return nil, false
}

func (cache *ipcacheV4) RunFuncOnLpmIP(ip net.IP, f func(val interface{}) bool) {
	cache.Lock()
	defer cache.Unlock()

	for i := len(cache.ipv4) - 1; i >= 0; i-- {
		m := cache.ipv4[i]
		if m != nil {
			val, ok := m[binary.BigEndian.Uint32(ip)&binary.BigEndian.Uint32(net.CIDRMask(i, 32))]
			if ok && f(val) {
				return
			}
		}
	}

}

func (cache *ipcacheV4) RunFuncOnVals(f func(val interface{}) interface{}) {
	cache.Lock()
	defer cache.Unlock()

	for mask, m := range cache.ipv4 {
		if m == nil {
			continue
		}

		for ip, val := range m {
			v := f(val)
			if v == nil {
				delete(m, ip)
				continue
			}

			m[ip] = v
		}

		if len(m) == 0 {
			cache.ipv4[mask] = nil
		}
	}

}

func (cache *ipcacheV6) Put(ip net.IP, mask int, val interface{}) {
	cache.Lock()
	defer cache.Unlock()

	if cache.ipv6[mask] == nil {
		cache.ipv6[mask] = map[[16]byte]interface{}{}
	}

	m := cache.ipv6[mask]
	// the following expression is ANDing the ip with the mask
	var maskip [16]byte
	copy(maskip[:], ip.Mask(net.CIDRMask(mask, 128)))
	m[maskip] = val
}

func (cache *ipcacheV6) Get(ip net.IP, mask int) (interface{}, bool) {
	cache.RLock()
	defer cache.RUnlock()

	m := cache.ipv6[mask]
	if m != nil {
		var maskip [16]byte
		copy(maskip[:], ip.Mask(net.CIDRMask(mask, 128)))
		val, ok := m[maskip]
		if ok {
			return val, true
		}
	}

	return nil, false
}

func (cache *ipcacheV6) RunFuncOnLpmIP(ip net.IP, f func(val interface{}) bool) {
	cache.Lock()
	defer cache.Unlock()

	for i := len(cache.ipv6) - 1; i >= 0; i-- {
		m := cache.ipv6[i]
		if m != nil {
			var maskip [16]byte
			copy(maskip[:], ip.Mask(net.CIDRMask(i, 128)))
			val, ok := m[maskip]
			if ok && f(val) {
				return
			}
		}
	}
}

func (cache *ipcacheV6) RunFuncOnVals(f func(val interface{}) interface{}) {
	cache.Lock()
	defer cache.Unlock()

	for mask, m := range cache.ipv6 {
		if m == nil {
			continue
		}

		for ip, val := range m {
			v := f(val)
			if v == nil {
				delete(m, ip)
				continue
			}

			m[ip] = v
		}

		if len(m) == 0 {
			cache.ipv6[mask] = nil
		}
	}
}

//NewIPCache creates an object which is implementing the interface IPcache
func NewIPCache() IPcache {
	return &ipcache{
		ipv4: &ipcacheV4{ipv4: make([]map[uint32]interface{}, ipv4MaskSize)},
		ipv6: &ipcacheV6{ipv6: make([]map[[16]byte]interface{}, ipv6MaskSize)},
	}
}

func (cache *ipcache) Put(ip net.IP, mask int, val interface{}) {
	if ip.To4() != nil {
		cache.ipv4.Put(ip.To4(), mask, val)
		return
	}

	cache.ipv6.Put(ip.To16(), mask, val)
}

func (cache *ipcache) Get(ip net.IP, mask int) (interface{}, bool) {

	if ip.To4() != nil {
		return cache.ipv4.Get(ip.To4(), mask)
	}

	return cache.ipv6.Get(ip.To16(), mask)
}

func (cache *ipcache) RunFuncOnLpmIP(ip net.IP, f FuncOnLpmIP) {
	if ip.To4() != nil {
		cache.ipv4.RunFuncOnLpmIP(ip.To4(), f)
		return
	}

	cache.ipv6.RunFuncOnLpmIP(ip.To16(), f)
}

func (cache *ipcache) RunFuncOnVals(f FuncOnVals) {

	cache.ipv4.RunFuncOnVals(f)
	cache.ipv6.RunFuncOnVals(f)
}
