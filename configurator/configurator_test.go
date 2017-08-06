package configurator

import (
	"os"
	"testing"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/enforcer/proxy"
	"github.com/aporeto-inc/trireme/enforcer/utils/rpcwrapper"
	"github.com/aporeto-inc/trireme/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/dockermonitor"
	"github.com/aporeto-inc/trireme/supervisor"
	"github.com/aporeto-inc/trireme/supervisor/proxy"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	keyPEM, caPool, certPEM string
	token                   []byte
)

func init() {
	keyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPkiHqtH372JJdAG/IxJlE1gv03cdwa8Lhg2b3m/HmbyoAoGCCqGSM49
AwEHoUQDQgAEAfAL+AfPj/DnxrU6tUkEyzEyCxnflOWxhouy1bdzhJ7vxMb1vQ31
8ZbW/WvMN/ojIXqXYrEpISoojznj46w64w==
-----END EC PRIVATE KEY-----`

	caPool = `-----BEGIN CERTIFICATE-----
MIIBhTCCASwCCQC8b53yGlcQazAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExDDAKBgNVBAcMA1NKQzEQMA4GA1UECgwHVHJpcmVtZTEPMA0G
A1UEAwwGdWJ1bnR1MB4XDTE2MDkyNzIyNDkwMFoXDTI2MDkyNTIyNDkwMFowSzEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQwwCgYDVQQHDANTSkMxEDAOBgNVBAoM
B1RyaXJlbWUxDzANBgNVBAMMBnVidW50dTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABJxneTUqhbtgEIwpKUUzwz3h92SqcOdIw3mfQkMjg3Vobvr6JKlpXYe9xhsN
rygJmLhMAN9gjF9qM9ybdbe+m3owCgYIKoZIzj0EAwIDRwAwRAIgC1fVMqdBy/o3
jNUje/Hx0fZF9VDyUK4ld+K/wF3QdK4CID1ONj/Kqinrq2OpjYdkgIjEPuXoOoR1
tCym8dnq4wtH
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB3jCCAYOgAwIBAgIJALsW7pyC2ERQMAoGCCqGSM49BAMCMEsxCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJDQTEMMAoGA1UEBwwDU0pDMRAwDgYDVQQKDAdUcmlyZW1l
MQ8wDQYDVQQDDAZ1YnVudHUwHhcNMTYwOTI3MjI0OTAwWhcNMjYwOTI1MjI0OTAw
WjBLMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExDDAKBgNVBAcMA1NKQzEQMA4G
A1UECgwHVHJpcmVtZTEPMA0GA1UEAwwGdWJ1bnR1MFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAE4c2Fd7XeIB1Vfs51fWwREfLLDa55J+NBalV12CH7YEAnEXjl47aV
cmNqcAtdMUpf2oz9nFVI81bgO+OSudr3CqNQME4wHQYDVR0OBBYEFOBftuI09mmu
rXjqDyIta1gT8lqvMB8GA1UdIwQYMBaAFOBftuI09mmurXjqDyIta1gT8lqvMAwG
A1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAMylAHhbFA0KqhXIFiXNpEbH
JKaELL6UXXdeQ5yup8q+AiEAh5laB9rbgTymjaANcZ2YzEZH4VFS3CKoSdVqgnwC
dW4=
-----END CERTIFICATE-----`

	certPEM = `-----BEGIN CERTIFICATE-----
MIIBhjCCASwCCQCPCdgp39gHJTAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExDDAKBgNVBAcMA1NKQzEQMA4GA1UECgwHVHJpcmVtZTEPMA0G
A1UEAwwGdWJ1bnR1MB4XDTE2MDkyNzIyNDkwMFoXDTI2MDkyNTIyNDkwMFowSzEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQwwCgYDVQQHDANTSkMxEDAOBgNVBAoM
B1RyaXJlbWUxDzANBgNVBAMMBnVidW50dTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABAHwC/gHz4/w58a1OrVJBMsxMgsZ35TlsYaLstW3c4Se78TG9b0N9fGW1v1r
zDf6IyF6l2KxKSEqKI854+OsOuMwCgYIKoZIzj0EAwIDSAAwRQIgQwQn0jnK/XvD
KxgQd/0pW5FOAaB41cMcw4/XVlphO1oCIQDlGie+WlOMjCzrV0Xz+XqIIi1pIgPT
IG7Nv+YlTVp5qA==
-----END CERTIFICATE-----`

	token = []byte{0x65, 0x79, 0x4A, 0x68, 0x62, 0x47, 0x63, 0x69, 0x4F, 0x69, 0x4A, 0x46, 0x55, 0x7A, 0x49, 0x31, 0x4E, 0x69, 0x49, 0x73, 0x49, 0x6E, 0x52, 0x35, 0x63, 0x43, 0x49, 0x36, 0x49, 0x6B, 0x70, 0x58, 0x56, 0x43, 0x4A, 0x39, 0x2E, 0x65, 0x79, 0x4A, 0x59, 0x49, 0x6A, 0x6F, 0x78, 0x4F, 0x44, 0x51, 0x32, 0x4E, 0x54, 0x6B, 0x78, 0x4D, 0x7A, 0x63, 0x33, 0x4E, 0x44, 0x41, 0x35, 0x4D, 0x7A, 0x4D, 0x35, 0x4D, 0x7A, 0x51, 0x33, 0x4D, 0x54, 0x4D, 0x77, 0x4D, 0x6A, 0x4D, 0x35, 0x4E, 0x6A, 0x45, 0x79, 0x4E, 0x6A, 0x55, 0x79, 0x4D, 0x7A, 0x45, 0x77, 0x4E, 0x44, 0x51, 0x30, 0x4F, 0x44, 0x63, 0x34, 0x4D, 0x7A, 0x45, 0x78, 0x4E, 0x6A, 0x4D, 0x30, 0x4E, 0x7A, 0x6B, 0x32, 0x4D, 0x6A, 0x4D, 0x32, 0x4D, 0x7A, 0x67, 0x30, 0x4E, 0x54, 0x59, 0x30, 0x4E, 0x6A, 0x51, 0x78, 0x4E, 0x7A, 0x67, 0x78, 0x4E, 0x44, 0x41, 0x78, 0x4F, 0x44, 0x63, 0x35, 0x4F, 0x44, 0x4D, 0x30, 0x4D, 0x44, 0x51, 0x78, 0x4E, 0x53, 0x77, 0x69, 0x57, 0x53, 0x49, 0x36, 0x4F, 0x44, 0x59, 0x78, 0x4F, 0x44, 0x41, 0x7A, 0x4E, 0x6A, 0x45, 0x33, 0x4D, 0x6A, 0x67, 0x34, 0x4D, 0x54, 0x6B, 0x79, 0x4D, 0x44, 0x41, 0x30, 0x4D, 0x6A, 0x41, 0x33, 0x4D, 0x44, 0x63, 0x30, 0x4D, 0x44, 0x6B, 0x78, 0x4D, 0x54, 0x41, 0x33, 0x4D, 0x54, 0x49, 0x33, 0x4D, 0x7A, 0x49, 0x78, 0x4F, 0x54, 0x45, 0x34, 0x4D, 0x54, 0x45, 0x77, 0x4F, 0x44, 0x41, 0x77, 0x4E, 0x54, 0x41, 0x79, 0x4F, 0x54, 0x59, 0x79, 0x4D, 0x6A, 0x49, 0x78, 0x4D, 0x54, 0x41, 0x32, 0x4E, 0x44, 0x41, 0x30, 0x4D, 0x54, 0x6B, 0x32, 0x4F, 0x54, 0x49, 0x34, 0x4D, 0x54, 0x55, 0x78, 0x4D, 0x6A, 0x55, 0x31, 0x4E, 0x54, 0x55, 0x30, 0x4F, 0x54, 0x63, 0x73, 0x49, 0x6D, 0x56, 0x34, 0x63, 0x43, 0x49, 0x36, 0x4D, 0x54, 0x55, 0x7A, 0x4D, 0x7A, 0x49, 0x30, 0x4D, 0x54, 0x6B, 0x78, 0x4D, 0x6E, 0x30, 0x2E, 0x56, 0x43, 0x44, 0x30, 0x54, 0x61, 0x4C, 0x69, 0x66, 0x74, 0x35, 0x63, 0x6A, 0x6E, 0x66, 0x74, 0x73, 0x7A, 0x57, 0x63, 0x43, 0x74, 0x56, 0x64, 0x59, 0x49, 0x63, 0x5A, 0x44, 0x58, 0x63, 0x73, 0x67, 0x66, 0x47, 0x41, 0x69, 0x33, 0x42, 0x77, 0x6F, 0x73, 0x4A, 0x50, 0x68, 0x6F, 0x76, 0x6A, 0x57, 0x65, 0x56, 0x65, 0x74, 0x6E, 0x55, 0x44, 0x44, 0x46, 0x69, 0x45, 0x37, 0x4E, 0x78, 0x76, 0x4E, 0x6A, 0x32, 0x52, 0x43, 0x53, 0x79, 0x4A, 0x76, 0x2D, 0x52, 0x6F, 0x71, 0x72, 0x6F, 0x78, 0x4E, 0x48, 0x4B, 0x4B, 0x37, 0x77}
}

func policyResolver() trireme.PolicyResolver {
	var newResolver trireme.PolicyResolver

	return newResolver
}

func procPacket() enforcer.PacketProcessor {
	var newProc enforcer.PacketProcessor

	return newProc
}

func eventCollector() collector.EventCollector {
	newEvent := &collector.DefaultCollector{}
	return newEvent
}

func secretGen(keyPEM, certPEM, caPool []byte) secrets.Secrets {

	if keyPEM == nil && certPEM == nil && caPool == nil {
		newSecret := NewSecretsFromPSK([]byte("Dummy Test Password"))
		return newSecret
	}
	newSecret := NewSecretsFromPKI([]byte(keyPEM), []byte(certPEM), []byte(caPool))
	return newSecret
}

func testEnforcerMap(sec, config string, pucon constants.PUType, puenfmode constants.ModeType) map[constants.PUType]enforcer.PolicyEnforcer {
	if sec == "psk" {
		if config == "hybrid" {
			return map[constants.PUType]enforcer.PolicyEnforcer{
				constants.ContainerPU:    testEnforcerProxy(),
				constants.LinuxProcessPU: testEnforcer(sec, puenfmode),
			}
		} else if config == "distributeddocker" {
			return map[constants.PUType]enforcer.PolicyEnforcer{
				pucon: testEnforcerProxy(),
			}
		} else {
			return map[constants.PUType]enforcer.PolicyEnforcer{
				pucon: testEnforcer(sec, puenfmode),
			}
		}
	}
	if config == "hybrid" {
		return map[constants.PUType]enforcer.PolicyEnforcer{
			constants.ContainerPU:    testEnforcerProxy(),
			constants.LinuxProcessPU: testEnforcer(sec, puenfmode),
		}
	} else if config == "distributeddocker" {
		return map[constants.PUType]enforcer.PolicyEnforcer{
			pucon: testEnforcerProxy(),
		}
	} else {
		return map[constants.PUType]enforcer.PolicyEnforcer{
			pucon: testEnforcer(sec, puenfmode),
		}
	}
}

func testEnforcer(sec string, puenfmode constants.ModeType) enforcer.PolicyEnforcer {
	if sec == "psk" {
		newEnf := enforcer.NewWithDefaults("testServerID", eventCollector(), nil, secretGen(nil, nil, nil), puenfmode, DefaultProcMountPoint)
		return newEnf
	}
	newEnf := enforcer.NewWithDefaults("testServerID", eventCollector(), nil, secretGen([]byte(keyPEM), []byte(certPEM), []byte(caPool)), puenfmode, DefaultProcMountPoint)
	return newEnf
}

func testSupervisorMap(sec, config string, impl constants.ImplementationType, pusup constants.PUType, pusupmode constants.ModeType, puconmode constants.ModeType) (map[constants.PUType]supervisor.Supervisor, error) {

	if config == "hybrid" {
		supp, err := testSupervisorProxy(sec, puconmode)
		if err != nil {
			return nil, err
		}
		sup, err := testSupervisor(sec, impl, pusupmode, puconmode)
		if err != nil {
			return nil, err
		}
		return map[constants.PUType]supervisor.Supervisor{
			constants.ContainerPU:    supp,
			constants.LinuxProcessPU: sup,
		}, nil
	} else if config == "distributeddocker" {
		sup, err := testSupervisorProxy(sec, puconmode)
		if err != nil {
			return nil, err
		}
		return map[constants.PUType]supervisor.Supervisor{
			pusup: sup,
		}, nil

	} else {
		sup, err := testSupervisor(sec, impl, pusupmode, puconmode)
		if err != nil {
			return nil, err
		}
		return map[constants.PUType]supervisor.Supervisor{
			pusup: sup,
		}, nil
	}
}

func testSupervisor(sec string, impl constants.ImplementationType, pusupmode constants.ModeType, puconmode constants.ModeType) (supervisor.Supervisor, error) {
	var newSup supervisor.Supervisor
	newSup, err := supervisor.NewSupervisor(eventCollector(), testEnforcer(sec, puconmode), pusupmode, impl, []string{})
	if err != nil {
		return nil, err
	}
	return newSup, nil
}

func testSupervisorProxy(sec string, puconmode constants.ModeType) (*supervisorproxy.ProxyInfo, error) {
	var newSup *supervisorproxy.ProxyInfo
	newSup, err := supervisorproxy.NewProxySupervisor(eventCollector(), testEnforcer(sec, puconmode), rpcwrapper.NewRPCWrapper())
	if err != nil {
		return nil, err
	}
	return newSup, nil
}

func testEnforcerProxy() enforcer.PolicyEnforcer {
	newEnf := enforcerproxy.NewDefaultProxyEnforcer("testServerID", eventCollector(), secretGen(nil, nil, nil), rpcwrapper.NewRPCWrapper(), DefaultProcMountPoint)
	return newEnf
}

func testTriremeStruct(sec, config string, impl constants.ImplementationType, pusup constants.PUType, pucon constants.PUType) trireme.Trireme {
	if sec == "psk" {
		if config == "localdocker" && pusup == constants.ContainerPU && pucon == constants.ContainerPU {
			sup, _ := testSupervisorMap(sec, config, impl, pusup, constants.LocalContainer, constants.LocalContainer)
			newTR := trireme.NewTrireme("testServerID", policyResolver(), sup, testEnforcerMap(sec, config, pucon, constants.LocalContainer), eventCollector())
			return newTR
		} else if config == "linux" && pusup == constants.ContainerPU && pucon == constants.LinuxProcessPU {
			sup, _ := testSupervisorMap(sec, config, impl, pusup, constants.LocalServer, constants.LocalServer)
			newTR := trireme.NewTrireme("testServerID", policyResolver(), sup, testEnforcerMap(sec, config, pucon, constants.LocalServer), eventCollector())
			return newTR
		} else if config == "distributeddocker" && pusup == constants.ContainerPU && pucon == constants.ContainerPU {
			sup, _ := testSupervisorMap(sec, config, impl, pusup, constants.LocalServer, constants.LocalServer)
			newTR := trireme.NewTrireme("testServerID", policyResolver(), sup, testEnforcerMap(sec, config, pucon, constants.LocalServer), eventCollector())
			return newTR
		} else if config == "hybrid" && pusup == constants.ContainerPU && pucon == constants.ContainerPU {
			sup, _ := testSupervisorMap(sec, config, impl, pusup, constants.LocalServer, constants.LocalServer)
			newTR := trireme.NewTrireme("testServerID", policyResolver(), sup, testEnforcerMap(sec, config, pucon, constants.LocalServer), eventCollector())
			return newTR
		}
	}
	if config == "localdocker" && pusup == constants.ContainerPU && pucon == constants.ContainerPU {
		sup, _ := testSupervisorMap(sec, config, impl, pusup, constants.LocalContainer, constants.LocalContainer)
		newTR := trireme.NewTrireme("testServerID", policyResolver(), sup, testEnforcerMap(sec, config, pucon, constants.LocalContainer), eventCollector())
		return newTR
	} else if config == "linux" && pusup == constants.ContainerPU && pucon == constants.LinuxProcessPU {
		sup, _ := testSupervisorMap(sec, config, impl, pusup, constants.LocalServer, constants.LocalServer)
		newTR := trireme.NewTrireme("testServerID", policyResolver(), sup, testEnforcerMap(sec, config, pucon, constants.LocalServer), eventCollector())
		return newTR
	} else if config == "distributeddocker" && pusup == constants.ContainerPU && pucon == constants.ContainerPU {
		sup, _ := testSupervisorMap(sec, config, impl, pusup, constants.LocalServer, constants.LocalServer)
		newTR := trireme.NewTrireme("testServerID", policyResolver(), sup, testEnforcerMap(sec, config, pucon, constants.LocalServer), eventCollector())
		return newTR
	} else if config == "hybrid" && pusup == constants.ContainerPU && pucon == constants.ContainerPU {
		sup, _ := testSupervisorMap(sec, config, impl, pusup, constants.LocalServer, constants.LocalServer)
		newTR := trireme.NewTrireme("testServerID", policyResolver(), sup, testEnforcerMap(sec, config, pucon, constants.LocalServer), eventCollector())
		return newTR
	}

	return nil
}

func testMonitorInstance(triremeInstance trireme.Trireme) monitor.Monitor {
	var mon monitor.Monitor
	var dm dockermonitor.DockerMetadataExtractor
	mon = dockermonitor.NewDockerMonitor(
		constants.DefaultDockerSocketType,
		constants.DefaultDockerSocket,
		triremeInstance,
		dm,
		nil,
		false,
		nil,
		false)
	return mon
}

func TestNewTriremeLinuxProcess(t *testing.T) {
	Convey("When I try to instantiate a new trireme linux process", t, func() {
		trirem := NewTriremeLinuxProcess("testServerID", policyResolver(), procPacket(), nil, secretGen(nil, nil, nil))

		Convey("Then I should get correct instantiation of all data structures", func() {
			So(trirem, ShouldResemble, testTriremeStruct("psk", "linux", constants.IPTables, constants.ContainerPU, constants.LinuxProcessPU))
		})
	})
}

func TestNewLocalTriremeDocker(t *testing.T) {
	Convey("When I try to instantiate a new local trireme docker", t, func() {
		trirem := NewLocalTriremeDocker("testServerID", policyResolver(), procPacket(), nil, secretGen(nil, nil, nil), constants.IPTables)

		Convey("Then I should get correct instantiation of all data structures", func() {
			So(trirem, ShouldResemble, testTriremeStruct("psk", "localdocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
		})
	})
}

func TestNewDistributedTriremeDocker(t *testing.T) {
	Convey("When I try to instantiate a new new distributed trireme docker", t, func() {
		trirem := NewDistributedTriremeDocker("testServerID", policyResolver(), procPacket(), nil, secretGen(nil, nil, nil), constants.IPTables)

		Convey("Then trireme struct should not match because of random server secret don't match", func() {
			So(trirem, ShouldNotResemble, testTriremeStruct("psk", "distributeddocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
		})
	})
}

func TestNewHybridTrireme(t *testing.T) {
	Convey("When I try to instantiate a new hybrid trireme", t, func() {
		trirem := NewHybridTrireme("testServerID", policyResolver(), procPacket(), nil, secretGen(nil, nil, nil), []string{"anyNetwork"})

		Convey("Then trireme struct should not match because of random server secret don't match", func() {
			So(trirem, ShouldNotResemble, testTriremeStruct("psk", "hybrid", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
		})
	})
}

func TestNewPSKTriremeWithDockerMonitor(t *testing.T) {
	Convey("When I try to instantiate a New PSK TriremeWith Docker Monitor with remote enforcer set to true", t, func() {
		var dm dockermonitor.DockerMetadataExtractor
		trirem, monitor := NewPSKTriremeWithDockerMonitor("testServerID", policyResolver(), procPacket(), nil, false, []byte("Dummy Test Password"), dm, true, false)

		Convey("Then trireme struct and monitor should not match because of random server secret don't match", func() {
			So(trirem, ShouldNotResemble, testTriremeStruct("psk", "distributeddocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
			So(monitor, ShouldNotResemble, testMonitorInstance(testTriremeStruct("psk", "distributeddocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU)))
		})
	})

	Convey("When I try to instantiate a New PSK TriremeWith Docker Monitor with remote enforcer set to false", t, func() {
		var dm dockermonitor.DockerMetadataExtractor
		trirem, monitor := NewPSKTriremeWithDockerMonitor("testServerID", policyResolver(), procPacket(), nil, false, []byte("Dummy Test Password"), dm, false, false)

		Convey("Then trireme struct should match and monitor should not match because of docker events", func() {
			So(trirem, ShouldResemble, testTriremeStruct("psk", "localdocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
			So(monitor, ShouldNotResemble, testMonitorInstance(testTriremeStruct("psk", "localdocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU)))
		})
	})
}

func TestNewPKITriremeWithDockerMonitor(t *testing.T) {
	Convey("When I try to instantiate a New PKI Trireme With Docker Monitor set to true", t, func() {
		var dm dockermonitor.DockerMetadataExtractor
		trirem, monitor, pkaddr := NewPKITriremeWithDockerMonitor("testServerID", policyResolver(), procPacket(), nil, false, []byte(keyPEM), []byte(certPEM), []byte(caPool), dm, true, false)

		Convey("Then trireme struct and monitor should not match because of random server secret don't match", func() {
			So(trirem, ShouldNotResemble, testTriremeStruct("pki", "distributeddocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
			So(monitor, ShouldNotResemble, testMonitorInstance(testTriremeStruct("pki", "distributeddocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU)))
			So(pkaddr, ShouldNotBeNil)
		})
	})

	Convey("When I try to instantiate a New PKI Trireme With Docker Monitor set to false", t, func() {
		var dm dockermonitor.DockerMetadataExtractor
		trirem, monitor, pkaddr := NewPKITriremeWithDockerMonitor("testServerID", policyResolver(), procPacket(), nil, false, []byte(keyPEM), []byte(certPEM), []byte(caPool), dm, false, false)

		Convey("Then trireme struct should match and monitor should not match because of docker events", func() {
			So(trirem, ShouldResemble, testTriremeStruct("pki", "localdocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
			So(monitor, ShouldNotResemble, testMonitorInstance(testTriremeStruct("pki", "localdocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU)))
			So(pkaddr, ShouldNotBeNil)
		})
	})

	Convey("When I try to instantiate a New PKI Trireme With Docker Monitor set to false and invalid secrets", t, func() {
		var dm dockermonitor.DockerMetadataExtractor
		trirem, monitor, pkaddr := NewPKITriremeWithDockerMonitor("testServerID", policyResolver(), procPacket(), nil, false, []byte("keyPEM"), []byte(certPEM), []byte(caPool), dm, false, false)

		Convey("Then trireme struct should match and monitor should not match because of docker events", func() {
			So(trirem, ShouldNotResemble, testTriremeStruct("pki", "localdocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
			So(monitor, ShouldNotResemble, testMonitorInstance(testTriremeStruct("pki", "localdocker", constants.IPTables, constants.ContainerPU, constants.ContainerPU)))
			So(pkaddr, ShouldBeNil)
		})
	})
}

func TestNewPSKHybridTriremeWithMonitor(t *testing.T) {
	Convey("When I try to instantiate a New PSK Hybrid Trireme With Monitor", t, func() {
		var dm dockermonitor.DockerMetadataExtractor
		trirem, monitor, _ := NewPSKHybridTriremeWithMonitor("testServerID", []string{"noNetwork"}, policyResolver(), procPacket(), nil, false, nil, dm, false)

		Convey("Then trireme struct should not match because of random server secret don't match", func() {
			So(trirem, ShouldNotResemble, testTriremeStruct("psk", "hybrid", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
			So(monitor, ShouldNotResemble, testMonitorInstance(testTriremeStruct("psk", "hybrid", constants.IPTables, constants.ContainerPU, constants.ContainerPU)))
		})
	})
}

func TestNewHybridCompactPKIWithDocker(t *testing.T) {
	Convey("When I try to instantiate a New PSK Hybrid Trireme With Monitor", t, func() {
		var dm dockermonitor.DockerMetadataExtractor
		trirem, monitor, _ := NewHybridCompactPKIWithDocker("testServerID", []string{"noNetwork"}, policyResolver(), procPacket(), nil, false, []byte(keyPEM), []byte(certPEM), []byte(caPool), token, dm, false, false)

		Convey("Then trireme struct should not match because of random server secret don't match", func() {
			So(trirem, ShouldNotResemble, testTriremeStruct("pki", "hybrid", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
			So(monitor, ShouldNotResemble, testMonitorInstance(testTriremeStruct("pki", "hybrid", constants.IPTables, constants.ContainerPU, constants.ContainerPU)))
		})
	})
}

func TestNewCompactPKIWithDocker(t *testing.T) {
	if os.Getenv("USER") != "root" {
		t.SkipNow()
	}

	Convey("When I try to instantiate a New PSK Hybrid Trireme With Monitor", t, func() {
		var dm dockermonitor.DockerMetadataExtractor
		trirem, monitor := NewCompactPKIWithDocker("testServerID", []string{"noNetwork"}, policyResolver(), procPacket(), nil, false, []byte(keyPEM), []byte(certPEM), []byte(caPool), token, dm, false, false)

		Convey("Then trireme struct should not match because of random server secret don't match", func() {
			So(trirem, ShouldNotResemble, testTriremeStruct("pki", "hybrid", constants.IPTables, constants.ContainerPU, constants.ContainerPU))
			So(monitor, ShouldNotResemble, testMonitorInstance(testTriremeStruct("pki", "hybrid", constants.IPTables, constants.ContainerPU, constants.ContainerPU)))
		})
	})
}
