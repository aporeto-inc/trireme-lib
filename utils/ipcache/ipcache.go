package ipcache

import (
	"encoding/binary"
	"net"
)

type IPcache interface {
	Put(net.IP, int, interface{})
	Get(net.IP, int) (interface{}, bool)
	RunVal(func(val interface{}) interface{})
	RunIP(net.IP, func(val interface{}) bool)
}

type ipcache struct {
	ipv4 map[int]map[uint32]interface{}
	ipv6 map[int]map[[16]byte]interface{}
}

func NewIPCache() *ipcache {
	return &ipcache{
		ipv4: map[int]map[uint32]interface{}{},
		ipv6: map[int]map[[16]byte]interface{}{},
	}
}

// Put replaces the old value
func (cache *ipcache) Put(ip net.IP, mask int, val interface{}) {
	if ip.To4() != nil {
		ip = ip.To4()
		if cache.ipv4[mask] == nil {
			cache.ipv4[mask] = map[uint32]interface{}{}
		}

		m := cache.ipv4[mask]
		// the following expression is ANDing the ip with the mask
		m[binary.BigEndian.Uint32(ip)&binary.BigEndian.Uint32(net.CIDRMask(mask, 32))] = val
	} else {
		ip = ip.To16()
		if cache.ipv6[mask] == nil {
			cache.ipv6[mask] = map[[16]byte]interface{}{}
		}

		m := cache.ipv6[mask]
		// the following expression is ANDing the ip with the mask
		var maskip [16]byte
		copy(maskip[:], ip.Mask(net.CIDRMask(mask, 128)))
		m[maskip] = val
	}
}

func (cache *ipcache) Get(ip net.IP, maskGet int) (interface{}, bool) {

	if ip.To4() != nil {
		ip = ip.To4()
		for mask, m := range cache.ipv4 {
			if mask == maskGet {
				val, ok := m[binary.BigEndian.Uint32(ip)&binary.BigEndian.Uint32(net.CIDRMask(mask, 32))]
				if ok {
					return val, true
				}
			}
		}
	} else {
		ip = ip.To16()
		for mask, m := range cache.ipv6 {
			if mask == maskGet {
				var maskip [16]byte
				copy(maskip[:], ip.Mask(net.CIDRMask(mask, 128)))

				val, ok := m[maskip]
				if ok {
					return val, true
				}
			}
		}
	}

	return nil, false
}

func (cache *ipcache) Find(ip net.IP) (interface{}, bool) {

	if ip.To4() != nil {
		ip = ip.To4()
		for mask, m := range cache.ipv4 {
			val, ok := m[binary.BigEndian.Uint32(ip)&binary.BigEndian.Uint32(net.CIDRMask(mask, 32))]
			if ok {
				return val, true
			}
		}
	} else {
		ip = ip.To16()
		for mask, m := range cache.ipv6 {
			var maskip [16]byte
			copy(maskip[:], ip.Mask(net.CIDRMask(mask, 128)))
			val, ok := m[maskip]
			if ok {
				return val, true
			}
		}
	}

	return nil, false
}

func (cache *ipcache) RunIP(ip net.IP, f func(val interface{}) bool) {
	if ip.To4() != nil {
		ip = ip.To4()
		for mask, m := range cache.ipv4 {
			val, ok := m[binary.BigEndian.Uint32(ip)&binary.BigEndian.Uint32(net.CIDRMask(mask, 32))]
			if ok {
				if f(val) {
					return
				}
			}
		}
	} else {
		ip = ip.To16()
		for mask, m := range cache.ipv6 {
			var maskip [16]byte
			copy(maskip[:], ip.Mask(net.CIDRMask(mask, 128)))
			val, ok := m[maskip]
			if ok {
				if f(val) {
					return
				}
			}
		}
	}

}

func (cache *ipcache) RunVal(f func(val interface{}) interface{}) {
	for mask, m := range cache.ipv4 {
		for ip, val := range m {
			v := f(val)
			if v == nil {
				delete(m, ip)
				continue
			}

			m[ip] = v
		}

		if len(m) == 0 {
			delete(cache.ipv4, mask)
		}
	}

	for mask, m := range cache.ipv6 {
		for ip, val := range m {
			v := f(val)
			if v == nil {
				delete(m, ip)
				continue
			}

			m[ip] = v
		}

		if len(m) == 0 {
			delete(cache.ipv6, mask)
		}
	}

}
