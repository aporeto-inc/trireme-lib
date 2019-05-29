package netinterfaces

import (
	"fmt"
	"net"

	"go.uber.org/zap"
)

// NetworkInterface holds info of a network interface
type NetworkInterface struct {
	Name   string
	IPs    []net.IP
	IPNets []*net.IPNet
	Flags  net.Flags
}

// GetInterfacesInfo returns interface info
func GetInterfacesInfo() ([]NetworkInterface, error) {

	netInterfaces := []NetworkInterface{}

	// List interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("unable to get interfaces: %v", err)
	}

	for _, intf := range ifaces {
		ipList := []net.IP{}
		ipNetList := []*net.IPNet{}

		// List interface addresses
		addrs, err := intf.Addrs()
		if err != nil {
			zap.L().Warn("unable to get interface addresses",
				zap.String("interface", intf.Name),
				zap.Error(err))
			continue
		}

		for _, addr := range addrs {
			ip, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				zap.L().Warn("unable to parse address",
					zap.String("interface", intf.Name),
					zap.String("addr", addr.String()),
					zap.Error(err))
				continue
			}

			ipList = append(ipList, ip)
			ipNetList = append(ipNetList, ipNet)
		}

		netInterface := NetworkInterface{
			Name:   intf.Name,
			IPs:    ipList,
			IPNets: ipNetList,
			Flags:  intf.Flags,
		}

		netInterfaces = append(netInterfaces, netInterface)
	}

	return netInterfaces, nil
}
