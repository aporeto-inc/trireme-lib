package dnsproxy

import (
	"net"
	"strconv"

	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/serviceregistry"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.uber.org/zap"
)

func configureDependentServices(puCtx *pucontext.PUContext, fqdn string, ips []string) {

	dependentServicesModified := false

	for _, dependentService := range puCtx.DependentServices(fqdn) {
		min, max := dependentService.NetworkInfo.Ports.Range()

		for _, ipString := range ips {
			if ip := net.ParseIP(ipString); ip.To4() != nil {
				if _, exists := dependentService.NetworkInfo.Addresses[ipString+"/32"]; exists {
					continue
				}
				_, ipNet, _ := net.ParseCIDR(ipString + "/32")
				for i := int(min); i <= int(max); i++ {
					if err := ipsetmanager.V4().AddIPPortToDependentService(puCtx.ID(), ipNet, strconv.Itoa(i)); err != nil {
						zap.L().Debug("dnsproxy: error adding dependent service ip port to ipset", zap.Error(err))
					}
				}
				dependentServicesModified = true
				dependentService.NetworkInfo.Addresses[ipNet.String()] = struct{}{}
			} else {
				if _, exists := dependentService.NetworkInfo.Addresses[ipString+"/128"]; exists {
					continue
				}
				_, ipNet, _ := net.ParseCIDR(ipString + "/128")
				for i := int(min); i <= int(max); i++ {
					if err := ipsetmanager.V6().AddIPPortToDependentService(puCtx.ID(), ipNet, strconv.Itoa(i)); err != nil {
						zap.L().Debug("dnsproxy: error adding dependent service ip port to ipset", zap.Error(err))
					}
				}
				dependentServicesModified = true
				dependentService.NetworkInfo.Addresses[ipNet.String()] = struct{}{}
			}
		}
	}

	if dependentServicesModified {
		if err := serviceregistry.Instance().UpdateDependentServicesByID(puCtx.ID()); err != nil {
			zap.L().Error("dnsproxy: error updating dependent services", zap.Error(err))
		}
	}
}
