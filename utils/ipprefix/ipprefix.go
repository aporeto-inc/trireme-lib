package ipprefix

import (
	"encoding/binary"
	"net"
	"sync"
)

//IPcache is an interface which provides functionality to store ip's and do longest prefix match
type IPcache interface {
	Put(net.IP, int, interface{})
	Get(net.IP, int) (interface{}, bool)
	RunVal(func(val interface{}) interface{})
	RunIP(net.IP, func(val interface{}) bool)
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

func (cache *ipcacheV4) RunIP(ip net.IP, f func(val interface{}) bool) {
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

func (cache *ipcacheV4) RunVal(f func(val interface{}) interface{}) {
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

func (cache *ipcacheV6) RunIP(ip net.IP, f func(val interface{}) bool) {
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

func (cache *ipcacheV6) RunVal(f func(val interface{}) interface{}) {
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

// Put takes an argument an ip address, mask and value. It is used as a cache for quick lookup
func (cache *ipcache) Put(ip net.IP, mask int, val interface{}) {
	if ip.To4() != nil {
		cache.ipv4.Put(ip.To4(), mask, val)
		return
	}

	cache.ipv6.Put(ip.To16(), mask, val)
}

// Get takes an argument the IP address and mask and returns the value that is stored for that key.
func (cache *ipcache) Get(ip net.IP, mask int) (interface{}, bool) {

	if ip.To4() != nil {
		return cache.ipv4.Get(ip.To4(), mask)
	}

	return cache.ipv6.Get(ip.To16(), mask)
}

// RunIP function takes as an argument an IP address and a function. It finds the subnet to which this IP belongs with the longest prefix match.
// It then calls the function supplied by the user on the value stored and if it succeeds then it returns.
func (cache *ipcache) RunIP(ip net.IP, f func(val interface{}) bool) {
	if ip.To4() != nil {
		cache.ipv4.RunIP(ip.To4(), f)
		return
	}

	cache.ipv6.RunIP(ip.To16(), f)
}

// RunVal takes an argument a function which is called on all the values stored in the
// cache. It updates the cache value with the new value that is returned by the function
func (cache *ipcache) RunVal(f func(val interface{}) interface{}) {

	cache.ipv4.RunVal(f)
	cache.ipv6.RunVal(f)
}
