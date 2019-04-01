package enforcerproxy

import (
	"context"
	"fmt"
	"testing"
	"time"

	gomock "github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/processmon/mockprocessmon"
	"go.aporeto.io/trireme-lib/controller/pkg/env"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packettracing"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

const procMountPoint = "/proc"

var (
	keypem, caPool, certPEM string
	token                   []byte
)

func init() {
	keypem = `-----BEGIN EC PRIVATE KEY-----
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

func eventCollector() collector.EventCollector {
	newEvent := &collector.DefaultCollector{}
	return newEvent
}

func secretGen() secrets.Secrets {

	_, newSecret, _ := secrets.CreateCompactPKITestSecrets()
	return newSecret
}

func createPUInfo() *policy.PUInfo {

	rules := policy.IPRuleList{
		policy.IPRule{
			Addresses: []string{"192.30.253.0/24"},
			Ports:     []string{"80"},
			Protocols: []string{"TCP"},
			Policy:    &policy.FlowPolicy{Action: policy.Reject},
		},

		policy.IPRule{
			Addresses: []string{"192.30.253.0/24"},
			Ports:     []string{"443"},
			Protocols: []string{"TCP"},
			Policy:    &policy.FlowPolicy{Action: policy.Accept},
		},
	}

	ips := policy.ExtendedMap{
		policy.DefaultNamespace: "172.17.0.1",
	}

	runtime := policy.NewPURuntimeWithDefaults()
	runtime.SetIPAddresses(ips)
	plc := policy.NewPUPolicy("testServerID", policy.Police, rules, rules, nil, nil, nil, nil, nil, ips, 0, nil, nil, []string{})

	return policy.PUInfoFromPolicyAndRuntime("testServerID", plc, runtime)

}

func setupProxyEnforcer() enforcer.Enforcer {
	mutualAuthorization := false
	fqConfig := fqconfig.NewFilterQueueWithDefaults()
	defaultExternalIPCacheTimeout := time.Second * 40
	validity := time.Hour * 8760
	policyEnf := NewProxyEnforcer(
		mutualAuthorization,
		fqConfig,
		eventCollector(),
		secretGen(),
		"testServerID",
		validity,
		constants.DefaultRemoteArg,
		procMountPoint,
		defaultExternalIPCacheTimeout,
		false,
		&runtime.Configuration{TCPTargetNetworks: []string{"0.0.0.0/0"}},
		make(chan *policy.RuntimeError),
		&env.RemoteParameters{},
	)
	return policyEnf
}

func TestNewDefaultProxyEnforcer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to start a proxy enforcer with defaults", t, func() {
		policyEnf := setupProxyEnforcer()

		e, ok := policyEnf.(*ProxyInfo)
		So(ok, ShouldBeTrue)
		Convey("Then policyEnf should be correct", func() {
			So(e, ShouldNotBeNil)
			So(e.rpchdl, ShouldNotBeNil)
			So(e.statsServerSecret, ShouldNotEqual, "")
		})
	})
}

func TestInitRemoteEnforcer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to start a proxy enforcer with defaults", t, func() {
		rpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
		policyEnf := setupProxyEnforcer()
		e := policyEnf.(*ProxyInfo)
		e.rpchdl = rpchdl

		Convey("When I try to initiate a remote enforcer", func() {
			rpchdl.EXPECT().RemoteCall("testServerID", remoteenforcer.InitEnforcer, gomock.Any(), gomock.Any()).Times(1).Return(nil)
			err := e.initRemoteEnforcer("testServerID")

			Convey("Then I should not get any error", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestEnforce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to start a proxy enforcer with defaults", t, func() {
		rpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
		prochdl := mockprocessmon.NewMockProcessManager(ctrl)
		policyEnf := setupProxyEnforcer()
		e := policyEnf.(*ProxyInfo)
		e.rpchdl = rpchdl
		e.prochdl = prochdl

		pu := createPUInfo()

		Convey("When launching the remote fails, it should error", func() {
			prochdl.EXPECT().LaunchRemoteEnforcer("pu", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, fmt.Errorf("error"))
			err := e.Enforce("pu", pu)
			So(err, ShouldNotBeNil)
		})

		Convey("When launching the remote succeeds, and init is false, but the rpc calls fails, it should work", func() {
			prochdl.EXPECT().LaunchRemoteEnforcer("pu", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
			rpchdl.EXPECT().RemoteCall("pu", remoteenforcer.Enforce, gomock.Any(), gomock.Any()).Return(fmt.Errorf("error"))
			prochdl.EXPECT().KillRemoteEnforcer("pu", true)
			err := e.Enforce("pu", pu)
			So(err, ShouldNotBeNil)
		})

		Convey("When launching the remote succeeds, and init is false, and rpc succeeds, it should work", func() {
			prochdl.EXPECT().LaunchRemoteEnforcer("pu", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
			rpchdl.EXPECT().RemoteCall("pu", remoteenforcer.Enforce, gomock.Any(), gomock.Any()).Return(nil)
			err := e.Enforce("pu", pu)
			So(err, ShouldBeNil)
		})

		Convey("When launching the remote succeeds, and init is true, and init of remote fails, it should error", func() {
			prochdl.EXPECT().LaunchRemoteEnforcer("pu", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
			rpchdl.EXPECT().RemoteCall("pu", remoteenforcer.InitEnforcer, gomock.Any(), gomock.Any()).Times(1).Return(fmt.Errorf("error"))
			prochdl.EXPECT().KillRemoteEnforcer("pu", true)
			err := e.Enforce("pu", pu)
			So(err, ShouldNotBeNil)
		})

		Convey("When launching succeeds with init true, it should not error", func() {
			prochdl.EXPECT().LaunchRemoteEnforcer("pu", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
			rpchdl.EXPECT().RemoteCall("pu", remoteenforcer.InitEnforcer, gomock.Any(), gomock.Any()).Times(1).Return(nil)
			rpchdl.EXPECT().RemoteCall("pu", remoteenforcer.Enforce, gomock.Any(), gomock.Any()).Return(nil)
			err := e.Enforce("pu", pu)
			So(err, ShouldBeNil)
		})
	})
}

func TestUnenforce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to start a proxy enforcer with defaults", t, func() {
		rpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
		prochdl := mockprocessmon.NewMockProcessManager(ctrl)
		policyEnf := setupProxyEnforcer()
		e := policyEnf.(*ProxyInfo)
		e.rpchdl = rpchdl
		e.prochdl = prochdl

		Convey("When I try to call unenforce", func() {
			rpchdl.EXPECT().RemoteCall("testServerID", remoteenforcer.Unenforce, gomock.Any(), gomock.Any()).Times(1).Return(nil)
			prochdl.EXPECT().KillRemoteEnforcer("testServerID", true)
			err := e.Unenforce("testServerID")
			So(err, ShouldBeNil)
		})

		Convey("When I try to call unenforce and there is a failure", func() {
			rpchdl.EXPECT().RemoteCall("testServerID", remoteenforcer.Unenforce, gomock.Any(), gomock.Any()).Times(1).Return(fmt.Errorf("error"))
			prochdl.EXPECT().KillRemoteEnforcer("testServerID", true)
			err := e.Unenforce("testServerID")

			Convey("Then I should not get an error", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestUpdateSecrets(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I update the secrets", t, func() {
		rpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
		prochdl := mockprocessmon.NewMockProcessManager(ctrl)
		policyEnf := setupProxyEnforcer()
		e := policyEnf.(*ProxyInfo)
		e.rpchdl = rpchdl
		e.prochdl = prochdl

		Convey("When there is no container, I should get no error", func() {
			rpchdl.EXPECT().ContextList().Return([]string{})
			err := e.UpdateSecrets(secretGen())
			So(err, ShouldBeNil)
		})

		Convey("When I get a set of PUs, I should update all of them", func() {
			rpchdl.EXPECT().ContextList().Return([]string{"pu1", "pu2"})
			rpchdl.EXPECT().RemoteCall("pu1", remoteenforcer.UpdateSecrets, gomock.Any(), gomock.Any())
			rpchdl.EXPECT().RemoteCall("pu2", remoteenforcer.UpdateSecrets, gomock.Any(), gomock.Any())

			err := e.UpdateSecrets(secretGen())
			So(err, ShouldBeNil)
		})

		Convey("When I get a set of PUs, and one of them fails, I should get an error", func() {
			rpchdl.EXPECT().ContextList().Return([]string{"pu1", "pu2"})
			rpchdl.EXPECT().RemoteCall("pu1", remoteenforcer.UpdateSecrets, gomock.Any(), gomock.Any()).Return(fmt.Errorf("error"))
			rpchdl.EXPECT().RemoteCall("pu2", remoteenforcer.UpdateSecrets, gomock.Any(), gomock.Any())

			err := e.UpdateSecrets(secretGen())
			So(err, ShouldNotBeNil)
		})
	})
}
func TestCleanup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I request a cleanup", t, func() {
		rpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
		prochdl := mockprocessmon.NewMockProcessManager(ctrl)
		policyEnf := setupProxyEnforcer()
		e := policyEnf.(*ProxyInfo)
		e.rpchdl = rpchdl
		e.prochdl = prochdl

		Convey("When there is no container, I should get no error", func() {
			rpchdl.EXPECT().ContextList().Return([]string{})
			err := e.CleanUp()
			So(err, ShouldBeNil)
		})

		Convey("When I get a set of PUs, I should call kill for all of them", func() {
			rpchdl.EXPECT().ContextList().Return([]string{"pu1", "pu2"})
			prochdl.EXPECT().KillRemoteEnforcer("pu1", false)
			prochdl.EXPECT().KillRemoteEnforcer("pu2", false)
			err := e.CleanUp()
			So(err, ShouldBeNil)
		})

		Convey("When I get a set of PUs, and one of them fails, I should get an error", func() {
			rpchdl.EXPECT().ContextList().Return([]string{"pu1", "pu2"})
			prochdl.EXPECT().KillRemoteEnforcer("pu1", false).Return(fmt.Errorf("error"))
			prochdl.EXPECT().KillRemoteEnforcer("pu2", false)
			err := e.CleanUp()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestEnableDatapathPacketTracing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to start a proxy enforcer with defaults", t, func() {
		rpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
		prochdl := mockprocessmon.NewMockProcessManager(ctrl)
		policyEnf := setupProxyEnforcer()
		e := policyEnf.(*ProxyInfo)
		e.rpchdl = rpchdl
		e.prochdl = prochdl

		Convey("When I try to call unenforce", func() {
			rpchdl.EXPECT().RemoteCall("testServerID", remoteenforcer.EnableDatapathPacketTracing, gomock.Any(), gomock.Any()).Times(1).Return(nil)
			err := e.EnableDatapathPacketTracing("testServerID", packettracing.NetworkOnly, 10*time.Second)
			So(err, ShouldBeNil)
		})

		Convey("When I try to call unenforce and there is a failure", func() {
			rpchdl.EXPECT().RemoteCall("testServerID", remoteenforcer.EnableDatapathPacketTracing, gomock.Any(), gomock.Any()).Times(1).Return(fmt.Errorf("error"))
			err := e.EnableDatapathPacketTracing("testServerID", packettracing.NetworkOnly, 10*time.Second)

			Convey("Then I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestEnableIPTablesPacketTracing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to start a proxy enforcer with defaults", t, func() {
		rpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
		prochdl := mockprocessmon.NewMockProcessManager(ctrl)
		policyEnf := setupProxyEnforcer()
		e := policyEnf.(*ProxyInfo)
		e.rpchdl = rpchdl
		e.prochdl = prochdl

		Convey("When I try to call unenforce", func() {
			rpchdl.EXPECT().RemoteCall("testServerID", remoteenforcer.EnableIPTablesPacketTracing, gomock.Any(), gomock.Any()).Times(1).Return(nil)
			err := e.EnableIPTablesPacketTracing(context.TODO(), "testServerID", 10*time.Second)
			So(err, ShouldBeNil)
		})

		Convey("When I try to call unenforce and there is a failure", func() {
			rpchdl.EXPECT().RemoteCall("testServerID", remoteenforcer.EnableIPTablesPacketTracing, gomock.Any(), gomock.Any()).Times(1).Return(fmt.Errorf("error"))
			err := e.EnableIPTablesPacketTracing(context.TODO(), "testServerID", 10*time.Second)

			Convey("Then I should get an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestSetTargetNetworks(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When update the target networks", t, func() {
		rpchdl := mockrpcwrapper.NewMockRPCClient(ctrl)
		prochdl := mockprocessmon.NewMockProcessManager(ctrl)
		policyEnf := setupProxyEnforcer()
		e := policyEnf.(*ProxyInfo)
		e.rpchdl = rpchdl
		e.prochdl = prochdl

		Convey("When there is no container, I should get no error", func() {
			rpchdl.EXPECT().ContextList().Return([]string{})
			err := e.SetTargetNetworks(&runtime.Configuration{})
			So(err, ShouldBeNil)
		})

		Convey("When I get a set of PUs, I should call kill for all of them", func() {
			rpchdl.EXPECT().ContextList().Return([]string{"pu1", "pu2"})
			rpchdl.EXPECT().RemoteCall("pu1", remoteenforcer.SetTargetNetworks, gomock.Any(), gomock.Any())
			rpchdl.EXPECT().RemoteCall("pu2", remoteenforcer.SetTargetNetworks, gomock.Any(), gomock.Any())
			err := e.SetTargetNetworks(&runtime.Configuration{})
			So(err, ShouldBeNil)
		})

		Convey("When I get a set of PUs, and one of them fails, I should get an error", func() {
			rpchdl.EXPECT().ContextList().Return([]string{"pu1", "pu2"})
			rpchdl.EXPECT().RemoteCall("pu1", remoteenforcer.SetTargetNetworks, gomock.Any(), gomock.Any()).Return(fmt.Errorf("error"))
			rpchdl.EXPECT().RemoteCall("pu2", remoteenforcer.SetTargetNetworks, gomock.Any(), gomock.Any())
			err := e.SetTargetNetworks(&runtime.Configuration{})
			So(err, ShouldNotBeNil)
		})
	})
}

func TestPostPacketEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	rpchdl := mockrpcwrapper.NewMockRPCServer(ctrl)
	c := eventCollector()
	packetreport := &collector.PacketReport{
		DestinationIP: "12.12.12.12",
		SourceIP:      "1.1.1.1",
	}
	request := rpcwrapper.Request{
		Payload: rpcwrapper.DebugPacketPayload{
			PacketRecords: []*collector.PacketReport{packetreport},
		},
	}
	statsserver := &StatsServer{
		rpchdl:    rpchdl,
		collector: c,
		secret:    "test",
	}
	response := &rpcwrapper.Response{}

	Convey("Given i receive a invalid message from the remote enforcer ", t, func() {
		rpchdl.EXPECT().ProcessMessage(gomock.Any(), gomock.Any()).Times(1).Return(false)
		err := statsserver.PostPacketEvent(request, response)
		So(err, ShouldNotBeNil)
	})

	Convey("Given i receive a valid message from the remote enforcer ", t, func() {
		rpchdl.EXPECT().ProcessMessage(gomock.Any(), gomock.Any()).Times(1).Return(true)
		err := statsserver.PostPacketEvent(request, response)
		So(err, ShouldBeNil)
	})
}
