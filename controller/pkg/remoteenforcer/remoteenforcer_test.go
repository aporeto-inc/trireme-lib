package remoteenforcer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/blang/semver"
	"github.com/golang/mock/gomock"
	"github.com/mitchellh/hashstructure"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/mockenforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/mocksupervisor"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/client/mockclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector/mockstatscollector"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/tokenissuer/mocktokenclient"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

const (
	PrivatePEMStr = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAPsuLuPc2dOYdYsuWx2OQOCHe+JpDhyi0JWUDaAIYuToAoGCCqGSM49
AwEHoUQDQgAEZo9Us5n6f59ibwslYg0MuE/r0UXh4rjl8CDoof+p/4mjmpxtizz3
QeHx2vEn9i1ziLWmNKzjK7BfdGx9OKgQlA==
-----END EC PRIVATE KEY-----`
	PublicPEMStr = `-----BEGIN CERTIFICATE-----
MIIB2TCCAX4CCQDYYXM0b/TZjDAKBggqhkjOPQQDAjB3MQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExEDAOBgNVBAoMB2Fwb3JldG8xIDAeBgNVBAsMF2Fwb3JldGFw
b3JldG8tZW5mb3JjZXJkMScwJQYDVQQDDB41YjYzODI5MGU1NDY0NDAwMDExMDdh
NjJAL2FtaXQwHhcNMTkwNzA4MTYyMjQ1WhcNMjcwOTI0MTYyMjQ1WjBxMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCQ0ExEDAOBgNVBAoMB2Fwb3JldG8xGjAYBgNVBAsM
EWFwb3JldG8tZW5mb3JjZXJkMScwJQYDVQQDDB41YjYzODI5MGU1NDY0NDAwMDEx
MDdhNzJAL2FtaXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARmj1Szmfp/n2Jv
CyViDQy4T+vRReHiuOXwIOih/6n/iaOanG2LPPdB4fHa8Sf2LXOItaY0rOMrsF90
bH04qBCUMAoGCCqGSM49BAMCA0kAMEYCIQCJvPURgA9dCQTdEfrwo7NHN+t4Dsxg
zRp0Co4jNpr7qwIhALDb9xmbxYs+p2tQwjgO+3OSSiQMumMGB8dG05cexXgq
-----END CERTIFICATE-----`
	CAPemStr = `-----BEGIN CERTIFICATE-----
MIICODCCAd6gAwIBAgIJAPN4RebDJxULMAoGCCqGSM49BAMCMHcxCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJDQTEQMA4GA1UECgwHYXBvcmV0bzEgMB4GA1UECwwXYXBv
cmV0YXBvcmV0by1lbmZvcmNlcmQxJzAlBgNVBAMMHjViNjM4MjkwZTU0NjQ0MDAw
MTEwN2E2MkAvYW1pdDAeFw0xOTA3MDgxNjE0NTZaFw0yOTA3MDUxNjE0NTZaMHcx
CzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEQMA4GA1UECgwHYXBvcmV0bzEgMB4G
A1UECwwXYXBvcmV0YXBvcmV0by1lbmZvcmNlcmQxJzAlBgNVBAMMHjViNjM4Mjkw
ZTU0NjQ0MDAwMTEwN2E2MkAvYW1pdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BPKtUhB7lyIOmkMqC9H3MxMG2CaOuY5qcGjsAq+Hq8VkPGzunZ5Q6QWRVp0WLl4O
JfEDjMbf66Cf9SY09n8HcBWjUzBRMB0GA1UdDgQWBBTEjMZZWURSMoCC/kMCvR/t
iGPU0jAfBgNVHSMEGDAWgBTEjMZZWURSMoCC/kMCvR/tiGPU0jAPBgNVHRMBAf8E
BTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDJyJ0jdJR5RIDEdvKFEH8SLWjrgtrs
8WeQejZF9D6x8wIgORPLU4AeDCVMYxPG87jEhoY+CHHZkcYPKOLn21B4uEk=
-----END CERTIFICATE-----`

	appQueueStr = "0:3"
	netQueueStr = "4:7"
	pcchan      = "/tmp/test.sock"
)

var (
	Token      []byte
	PrivatePEM []byte
	PublicPEM  []byte
	CAPem      []byte
)

func init() {

	PrivatePEM = []byte(PrivatePEMStr)
	PublicPEM = []byte(PublicPEMStr)
	CAPem = []byte(CAPemStr)

	Token = []byte{0x65, 0x79, 0x4A, 0x68, 0x62, 0x47, 0x63, 0x69, 0x4F, 0x69, 0x4A, 0x46, 0x55, 0x7A, 0x49, 0x31, 0x4E, 0x69, 0x49, 0x73, 0x49, 0x6E, 0x52, 0x35, 0x63, 0x43, 0x49, 0x36, 0x49, 0x6B, 0x70, 0x58, 0x56, 0x43, 0x4A, 0x39, 0x2E, 0x65, 0x79, 0x4A, 0x59, 0x49, 0x6A, 0x6F, 0x78, 0x4F, 0x44, 0x51, 0x32, 0x4E, 0x54, 0x6B, 0x78, 0x4D, 0x7A, 0x63, 0x33, 0x4E, 0x44, 0x41, 0x35, 0x4D, 0x7A, 0x4D, 0x35, 0x4D, 0x7A, 0x51, 0x33, 0x4D, 0x54, 0x4D, 0x77, 0x4D, 0x6A, 0x4D, 0x35, 0x4E, 0x6A, 0x45, 0x79, 0x4E, 0x6A, 0x55, 0x79, 0x4D, 0x7A, 0x45, 0x77, 0x4E, 0x44, 0x51, 0x30, 0x4F, 0x44, 0x63, 0x34, 0x4D, 0x7A, 0x45, 0x78, 0x4E, 0x6A, 0x4D, 0x30, 0x4E, 0x7A, 0x6B, 0x32, 0x4D, 0x6A, 0x4D, 0x32, 0x4D, 0x7A, 0x67, 0x30, 0x4E, 0x54, 0x59, 0x30, 0x4E, 0x6A, 0x51, 0x78, 0x4E, 0x7A, 0x67, 0x78, 0x4E, 0x44, 0x41, 0x78, 0x4F, 0x44, 0x63, 0x35, 0x4F, 0x44, 0x4D, 0x30, 0x4D, 0x44, 0x51, 0x78, 0x4E, 0x53, 0x77, 0x69, 0x57, 0x53, 0x49, 0x36, 0x4F, 0x44, 0x59, 0x78, 0x4F, 0x44, 0x41, 0x7A, 0x4E, 0x6A, 0x45, 0x33, 0x4D, 0x6A, 0x67, 0x34, 0x4D, 0x54, 0x6B, 0x79, 0x4D, 0x44, 0x41, 0x30, 0x4D, 0x6A, 0x41, 0x33, 0x4D, 0x44, 0x63, 0x30, 0x4D, 0x44, 0x6B, 0x78, 0x4D, 0x54, 0x41, 0x33, 0x4D, 0x54, 0x49, 0x33, 0x4D, 0x7A, 0x49, 0x78, 0x4F, 0x54, 0x45, 0x34, 0x4D, 0x54, 0x45, 0x77, 0x4F, 0x44, 0x41, 0x77, 0x4E, 0x54, 0x41, 0x79, 0x4F, 0x54, 0x59, 0x79, 0x4D, 0x6A, 0x49, 0x78, 0x4D, 0x54, 0x41, 0x32, 0x4E, 0x44, 0x41, 0x30, 0x4D, 0x54, 0x6B, 0x32, 0x4F, 0x54, 0x49, 0x34, 0x4D, 0x54, 0x55, 0x78, 0x4D, 0x6A, 0x55, 0x31, 0x4E, 0x54, 0x55, 0x30, 0x4F, 0x54, 0x63, 0x73, 0x49, 0x6D, 0x56, 0x34, 0x63, 0x43, 0x49, 0x36, 0x4D, 0x54, 0x55, 0x7A, 0x4D, 0x7A, 0x49, 0x30, 0x4D, 0x54, 0x6B, 0x78, 0x4D, 0x6E, 0x30, 0x2E, 0x56, 0x43, 0x44, 0x30, 0x54, 0x61, 0x4C, 0x69, 0x66, 0x74, 0x35, 0x63, 0x6A, 0x6E, 0x66, 0x74, 0x73, 0x7A, 0x57, 0x63, 0x43, 0x74, 0x56, 0x64, 0x59, 0x49, 0x63, 0x5A, 0x44, 0x58, 0x63, 0x73, 0x67, 0x66, 0x47, 0x41, 0x69, 0x33, 0x42, 0x77, 0x6F, 0x73, 0x4A, 0x50, 0x68, 0x6F, 0x76, 0x6A, 0x57, 0x65, 0x56, 0x65, 0x74, 0x6E, 0x55, 0x44, 0x44, 0x46, 0x69, 0x45, 0x37, 0x4E, 0x78, 0x76, 0x4E, 0x6A, 0x32, 0x52, 0x43, 0x53, 0x79, 0x4A, 0x76, 0x2D, 0x52, 0x6F, 0x71, 0x72, 0x6F, 0x78, 0x4E, 0x48, 0x4B, 0x4B, 0x37, 0x77}
}

func initTestEnfReqPayload() rpcwrapper.InitRequestPayload {
	var initEnfPayload rpcwrapper.InitRequestPayload

	initEnfPayload.Validity = constants.DatapathTokenValidity
	initEnfPayload.MutualAuth = true
	initEnfPayload.ServerID = "598236b81c252c000102665d"
	initEnfPayload.FqConfig = filterQ()

	s, err := secrets.NewCompactPKI(PrivatePEM, PublicPEM, CAPem, Token, claimsheader.CompressionTypeNone)
	if err != nil {
		fmt.Println("CompackPKI creation failed with:", err)
	}
	initEnfPayload.Secrets = s.PublicSecrets()
	initEnfPayload.Configuration = &runtime.Configuration{}
	return initEnfPayload
}

func filterQ() *fqconfig.FilterQueue {
	var initFilterQ fqconfig.FilterQueue

	initFilterQ.QueueSeparation = false
	initFilterQ.MarkValue = 1000
	initFilterQ.NetworkQueue = 4
	initFilterQ.NumberOfApplicationQueues = 4
	initFilterQ.NumberOfNetworkQueues = 4
	initFilterQ.ApplicationQueue = 0
	initFilterQ.ApplicationQueueSize = 500
	initFilterQ.NetworkQueueSize = 500
	initFilterQ.NetworkQueuesSynStr = netQueueStr
	initFilterQ.NetworkQueuesAckStr = netQueueStr
	initFilterQ.NetworkQueuesSynAckStr = netQueueStr
	initFilterQ.NetworkQueuesSvcStr = netQueueStr
	initFilterQ.ApplicationQueuesSynStr = appQueueStr
	initFilterQ.ApplicationQueuesAckStr = appQueueStr
	initFilterQ.ApplicationQueuesSvcStr = appQueueStr
	initFilterQ.ApplicationQueuesSynAckStr = appQueueStr

	return &initFilterQ
}

func initIdentity(id string) *policy.TagStore {
	var initID policy.TagStore

	initID.Tags = []string{id}

	return &initID
}

func initAnnotations(an string) *policy.TagStore {
	var initAnno policy.TagStore

	initAnno.Tags = []string{an}

	return &initAnno
}

func initTrans() policy.TagSelectorList {

	var tags policy.TagSelectorList
	var tag policy.TagSelector
	var keyval policy.KeyValueOperator
	var action policy.FlowPolicy
	var accept policy.ActionType

	keyval.Key = "@usr:role"
	keyval.Value = []string{"server"}
	keyval.Operator = "="
	accept = policy.Accept
	action.Action = accept
	tag.Clause = []policy.KeyValueOperator{keyval}
	tag.Policy = &action
	tags = []policy.TagSelector{tag}

	return tags
}

func getHash(payload interface{}) []byte {
	hash, err := hashstructure.Hash(payload, nil)
	if err != nil {
		return []byte{}
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, hash)
	return buf
}

func initTestEnfPayload() rpcwrapper.EnforcePayload {

	var initPayload rpcwrapper.EnforcePayload
	idString := "@usr:role=client $namespace=/sibicentos AporetoContextID=5983bc8c923caa0001337b11"
	anoString := "@sys:name=/inspiring_roentgen $namespace=/sibicentos @usr:build-date=20170801 @usr:license=GPLv2 @usr:name=CentOS Base Image @usr:role=client @usr:vendor=CentOS $id=5983bc8c923caa0001337b11 $namespace=/sibicentos $operationalstatus=Running $protected=false $type=Docker $description=centos $enforcerid=5983bba4923caa0001337a19 $name=centos $nativecontextid=b06f47830f64 @sys:image=centos @usr:role=client role=client $id=5983bc8c923caa0001337b11 $identity=processingunit $id=5983bc8c923caa0001337b11 $namespace=/sibicentos"

	initPayload.ContextID = "b06f47830f64"
	initPayload.Policy = &policy.PUPolicyPublic{
		ManagementID:     "5983bc8c923caa0001337b11",
		TriremeAction:    2,
		IPs:              policy.ExtendedMap{"bridge": "172.17.0.2"},
		Identity:         initIdentity(idString),
		Annotations:      initAnnotations(anoString),
		CompressedTags:   policy.NewTagStore(),
		TransmitterRules: initTrans(),
	}

	return initPayload
}

func initTestUnEnfPayload() rpcwrapper.UnEnforcePayload {

	var initPayload rpcwrapper.UnEnforcePayload

	initPayload.ContextID = "b06f47830f64"

	return initPayload
}

func Test_NewRemoteEnforcer(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to retrieve rpc server handle", t, func() {

		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)
		statsClient := mockclient.NewMockReporter(ctrl)
		reportsClient := mockclient.NewMockReporter(ctrl)
		collector := mockstatscollector.NewMockCollector(ctrl)
		tokenclient := mocktokenclient.NewMockTokenClient(ctrl)
		Convey("When I try to create new server with no env set", func() {
			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			rpcHdl.EXPECT().StartServer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			server, err := newRemoteEnforcer(ctx, cancel, nil, rpcHdl, "mysecret", statsClient, collector, reportsClient, tokenclient, zap.Config{}, policy.EnforcerMapping, semver.Version{})

			Convey("Then I should get error for no stats", func() {
				So(err, ShouldBeNil)
				So(server, ShouldNotBeNil)
				So(server.service, ShouldBeNil)
				So(server.rpcHandle, ShouldEqual, rpcHdl)
				So(server.procMountPoint, ShouldResemble, constants.DefaultProcMountPoint)
				So(server.statsClient, ShouldEqual, statsClient)
				So(server.reportsClient, ShouldEqual, reportsClient)
				So(server.ctx, ShouldEqual, ctx)
				So(server.cancel, ShouldEqual, cancel)
				So(server.exit, ShouldNotBeNil)
			})
		})
	})
}

func TestInitEnforcer(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to retrieve rpc server handle", t, func() {
		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)
		mockEnf := mockenforcer.NewMockEnforcer(ctrl)
		mockStats := mockclient.NewMockReporter(ctrl)
		mockReports := mockclient.NewMockReporter(ctrl)
		mockCollector := mockstatscollector.NewMockCollector(ctrl)
		mockSupevisor := mocksupervisor.NewMockSupervisor(ctrl)
		mockTokenClient := mocktokenclient.NewMockTokenClient(ctrl)

		// Mock the global functions.
		createEnforcer = func(
			mutualAuthorization bool,
			fqConfig *fqconfig.FilterQueue,
			collector collector.EventCollector,
			service packetprocessor.PacketProcessor,
			secrets secrets.Secrets,
			serverID string,
			validity time.Duration,
			mode constants.ModeType,
			procMountPoint string,
			externalIPCacheTimeout time.Duration,
			packetLogs bool,
			cfg *runtime.Configuration,
			tokenIssuer common.ServiceTokenIssuer,
			binaryTokens bool,
			aclmanager ipsetmanager.ACLManager,
			iseBPFSupported bool,
			agentVersion semver.Version,
		) (enforcer.Enforcer, error) {
			return mockEnf, nil
		}

		createSupervisor = func(
			collector collector.EventCollector,
			enforcerInstance enforcer.Enforcer,
			mode constants.ModeType,
			cfg *runtime.Configuration,
			p packetprocessor.PacketProcessor,
			aclmanager ipsetmanager.ACLManager,
			ipv6Enabled bool,
		) (supervisor.Supervisor, error) {
			return mockSupevisor, nil
		}
		defer func() {
			createSupervisor = supervisor.NewSupervisor
			createEnforcer = enforcer.New
		}()

		Convey("When I try to create new server with env set", func() {
			serr := os.Setenv(constants.EnvStatsChannel, pcchan)
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "T6UYZGcKW-aum_vi-XakafF3vHV7F6x8wdofZs7akGU=")
			So(serr, ShouldBeNil)
			var service packetprocessor.PacketProcessor

			secret := "T6UYZGcKW-aum_vi-XakafF3vHV7F6x8wdofZs7akGU="
			ctx, cancel := context.WithCancel(context.Background())
			server, err := newRemoteEnforcer(ctx, cancel, service, rpcHdl, secret, mockStats, mockCollector, mockReports, mockTokenClient, zap.Config{}, policy.EnforcerMapping, semver.Version{})
			So(err, ShouldBeNil)

			Convey("When I try to initiate an enforcer with invalid secret", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(false)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldResemble, errors.New("init message authentication failed"))
				})
			})

			Convey("When I try to instantiate the enforcer with a bad payload, it should error ", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfPayload()

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldResemble, errors.New("invalid request payload"))
				})
			})

			Convey("When I try to instantiate the enforcer amd the enforcer is initialized, it should fail ", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				server.enforcer = mockEnf

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldResemble, errors.New("remote enforcer is already initialized"))
				})
			})

			Convey("When I try to instantiate the enforcer and the enforcer fails, it should fail and cleanup", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				createEnforcer = func(
					mutualAuthorization bool,
					fqConfig *fqconfig.FilterQueue,
					collector collector.EventCollector,
					service packetprocessor.PacketProcessor,
					secrets secrets.Secrets,
					serverID string,
					validity time.Duration,
					mode constants.ModeType,
					procMountPoint string,
					externalIPCacheTimeout time.Duration,
					packetLogs bool,
					cfg *runtime.Configuration,
					tokenIssuer common.ServiceTokenIssuer,
					binaryTokens bool,
					aclmanager ipsetmanager.ACLManager,
					iseBPFSupported bool,
					agentVersion semver.Version,
				) (enforcer.Enforcer, error) {
					return nil, fmt.Errorf("failed enforcer")
				}

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("Error while initializing remote enforcer, failed enforcer"))
				})
			})

			Convey("When I try to instantiate the enforcer and the supervisor fails, it should fail", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				createSupervisor = func(
					collector collector.EventCollector,
					enforcerInstance enforcer.Enforcer,
					mode constants.ModeType,
					cfg *runtime.Configuration,
					p packetprocessor.PacketProcessor,
					aclmanager ipsetmanager.ACLManager,
					ipv6Enabled bool,
				) (supervisor.Supervisor, error) {
					return nil, fmt.Errorf("failed supervisor")
				}

				mockEnf.EXPECT().CleanUp()

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("unable to setup supervisor: failed supervisor"))
				})
			})

			Convey("When I try to instantiate the enforcer and the controller fails to run, it should clean up", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				mockEnf.EXPECT().Run(server.ctx).Return(fmt.Errorf("enforcer run error"))
				mockSupevisor.EXPECT().CleanUp()
				mockEnf.EXPECT().CleanUp()

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("enforcer run error"))
				})
			})

			Convey("When I try to instantiate the enforcer and the statclient fails to run, it should clean up", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				mockEnf.EXPECT().Run(server.ctx).Return(nil)
				mockStats.EXPECT().Run(server.ctx).Return(fmt.Errorf("stats error"))
				mockSupevisor.EXPECT().CleanUp()
				mockEnf.EXPECT().CleanUp()

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("stats error"))
				})
			})

			Convey("When I try to instantiate the enforcer and the supervisor fails to run, it should clean up", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				mockEnf.EXPECT().Run(server.ctx).Return(nil)
				mockStats.EXPECT().Run(server.ctx).Return(nil)
				mockSupevisor.EXPECT().Run(server.ctx).Return(fmt.Errorf("supervisor run"))
				mockSupevisor.EXPECT().CleanUp()
				mockEnf.EXPECT().CleanUp()

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("supervisor run"))
				})
			})

			Convey("When i try to instantiate the enforcer and reports Client fails to run it should cleanup", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				mockEnf.EXPECT().Run(server.ctx).Return(nil)
				mockStats.EXPECT().Run(server.ctx).Return(nil)
				mockSupevisor.EXPECT().Run(server.ctx).Return(nil)
				mockReports.EXPECT().Run(server.ctx).Return(errors.New("failed to run counterclient"))
				mockSupevisor.EXPECT().CleanUp()
				mockEnf.EXPECT().CleanUp()

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("ReportsClientfailed to run counterclient"))
				})

			})
			Convey("When I try to instantiate the enforcer and it succeeds it should not error", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				mockEnf.EXPECT().Run(server.ctx).Return(nil)
				mockStats.EXPECT().Run(server.ctx).Return(nil)
				mockSupevisor.EXPECT().Run(server.ctx).Return(nil)
				mockReports.EXPECT().Run(server.ctx).Return(nil)
				mockTokenClient.EXPECT().Run(server.ctx).Return(nil)
				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should not get error", func() {
					So(err, ShouldBeNil)
				})
			})

		})
	})
}

func TestEnforce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to retrieve rpc server handle", t, func() {
		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)
		mockEnf := mockenforcer.NewMockEnforcer(ctrl)
		mockSup := mocksupervisor.NewMockSupervisor(ctrl)
		ctx, cancel := context.WithCancel(context.TODO())

		Convey("When I try to create new server with env set", func() {

			server := &RemoteEnforcer{
				rpcHandle:  rpcHdl,
				supervisor: mockSup,
				enforcer:   mockEnf,
				ctx:        ctx,
				cancel:     cancel,
			}

			Convey("When I try to send enforce command with invalid secret", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(false)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0xDE, 0xBD, 0x1C, 0x6A, 0x2A, 0x51, 0xC0, 0x02, 0x4B, 0xD7, 0xD1, 0x82, 0x78, 0x8A, 0xC4, 0xF1, 0xBE, 0xBF, 0x00, 0x89, 0x47, 0x0F, 0x13, 0x71, 0xAB, 0x4C, 0x0D, 0xD9, 0x9D, 0x85, 0x45, 0x04}
				rpcwrperreq.Payload = initTestEnfPayload()
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte("InvalidSecret"))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)
				server.enforcer = mockEnf

				err := server.Enforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("enforce message auth failed"))
				})
			})

			Convey("When I try to send enforce command with wrong payload it should fail", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				err := server.Enforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("invalid enforcer payload"))
				})
			})

			Convey("When I try to send enforce command and the supervisor is nil, it should fail", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfPayload()
				server.supervisor = nil

				err := server.Enforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("enforcer not initialized - cannot enforce"))
				})
			})

			Convey("When I try to send enforce command and the supervisor fails, it should fail and cleanup", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockSup.EXPECT().Supervise(gomock.Any(), gomock.Any()).Return(fmt.Errorf("supervisor error"))
				mockSup.EXPECT().CleanUp()
				mockEnf.EXPECT().CleanUp()

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfPayload()

				err := server.Enforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("supervisor error"))
				})
			})

			Convey("When I try to send enforce command and the enforcer fails, it should fail and cleanup", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockSup.EXPECT().Supervise(gomock.Any(), gomock.Any()).Return(nil)
				mockEnf.EXPECT().Enforce(gomock.Any(), gomock.Any()).Return(fmt.Errorf("enforcer error"))
				mockSup.EXPECT().CleanUp()
				mockEnf.EXPECT().CleanUp()

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfPayload()

				err := server.Enforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("enforcer error"))
				})
			})

			Convey("When the enforce command succeeds, I should get no errors", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockSup.EXPECT().Supervise(gomock.Any(), gomock.Any()).Return(nil)
				mockEnf.EXPECT().Enforce(gomock.Any(), gomock.Any()).Return(nil)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfPayload()

				err := server.Enforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should not get an error ", func() {
					So(err, ShouldBeNil)
				})
			})
		})
	})
}

func Test_UnEnforce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a new server", t, func() {
		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)
		mockEnf := mockenforcer.NewMockEnforcer(ctrl)
		mockSup := mocksupervisor.NewMockSupervisor(ctrl)
		mockStats := mockclient.NewMockReporter(ctrl)
		ctx, cancel := context.WithCancel(context.TODO())

		Convey("With proper initialization", func() {

			server := &RemoteEnforcer{
				rpcHandle:   rpcHdl,
				supervisor:  mockSup,
				enforcer:    mockEnf,
				ctx:         ctx,
				cancel:      cancel,
				statsClient: mockStats,
			}

			Convey("When I try to send unenforce command with invalid secret", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(false)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestUnEnfPayload()
				rpcwrperres.Status = ""

				err := server.Unenforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("unenforce message auth failed"))
				})
			})

			Convey("When I try to send unenforce command with wrong payload it should fail", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockStats.EXPECT().Send()
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				err := server.Unenforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("invalid unenforcer payload"))
				})
			})

			Convey("When I try to send unenforce command and the supervisor fails, it should fail and cleanup", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockStats.EXPECT().Send()
				mockSup.EXPECT().Unsupervise(gomock.Any()).Return(fmt.Errorf("supervisor error"))
				mockSup.EXPECT().CleanUp()
				mockEnf.EXPECT().CleanUp()

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestUnEnfPayload()

				err := server.Unenforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("unable to clean supervisor: supervisor error"))
				})
			})

			Convey("When I try to send unenforce command and the enforcer fails, it should fail and cleanup", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockStats.EXPECT().Send()
				mockSup.EXPECT().Unsupervise(gomock.Any()).Return(nil)
				mockEnf.EXPECT().Unenforce(gomock.Any()).Return(fmt.Errorf("enforcer error"))
				mockSup.EXPECT().CleanUp()
				mockEnf.EXPECT().CleanUp()

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestUnEnfPayload()

				err := server.Unenforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("unable to stop enforcer: enforcer error"))
				})
			})

			Convey("When the enforce command succeeds, I should get no errors", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockStats.EXPECT().Send()
				mockSup.EXPECT().Unsupervise(gomock.Any()).Return(nil)
				mockEnf.EXPECT().Unenforce(gomock.Any()).Return(nil)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestUnEnfPayload()

				err := server.Unenforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should not get an error ", func() {
					So(err, ShouldBeNil)
				})
			})
		})
	})
}

func Test_EnableDatapathPacketTracing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a new server", t, func() {
		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)
		mockEnf := mockenforcer.NewMockEnforcer(ctrl)
		ctx, cancel := context.WithCancel(context.TODO())

		Convey("With proper initialization", func() {

			server := &RemoteEnforcer{
				rpcHandle: rpcHdl,
				enforcer:  mockEnf,
				ctx:       ctx,
				cancel:    cancel,
			}

			Convey("When I try to enable datapath tracing and the validity fails, it should fail", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(false)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = rpcwrapper.EnableDatapathPacketTracingPayLoad{}
				rpcwrperres.Status = ""

				err := server.EnableDatapathPacketTracing(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("enable datapath packet tracing auth failed"))
				})
			})

			Convey("When I try to enable datapath tracing  and the enforcer fails, it should fail and cleanup", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockEnf.EXPECT().EnableDatapathPacketTracing(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("error"))

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = rpcwrapper.EnableDatapathPacketTracingPayLoad{}

				err := server.EnableDatapathPacketTracing(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("error"))
				})
			})

			Convey("When the enforce command succeeds, I should get no errors", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockEnf.EXPECT().EnableDatapathPacketTracing(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = rpcwrapper.EnableDatapathPacketTracingPayLoad{}

				err := server.EnableDatapathPacketTracing(rpcwrperreq, &rpcwrperres)

				Convey("Then I should not get an error ", func() {
					So(err, ShouldBeNil)
				})
			})
		})
	})
}

func Test_EnableIPTablesPacketTracing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("Given a new server", t, func() {
		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)
		mockSup := mocksupervisor.NewMockSupervisor(ctrl)
		ctx, cancel := context.WithCancel(context.TODO())

		Convey("With proper initialization", func() {

			server := &RemoteEnforcer{
				rpcHandle:  rpcHdl,
				supervisor: mockSup,
				ctx:        ctx,
				cancel:     cancel,
			}

			Convey("When I try to enable datapath tracing and the validity fails, it should fail", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(false)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = rpcwrapper.EnableIPTablesPacketTracingPayLoad{}
				rpcwrperres.Status = ""

				err := server.EnableIPTablesPacketTracing(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("enable iptable packet tracing auth failed"))
				})
			})

			Convey("When I try to enable datapath tracing  and the enforcer fails, it should fail and cleanup", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockSup.EXPECT().EnableIPTablesPacketTracing(gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("error"))

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = rpcwrapper.EnableIPTablesPacketTracingPayLoad{}

				err := server.EnableIPTablesPacketTracing(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("error"))
				})
			})

			Convey("When the enforce command succeeds, I should get no errors", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), gomock.Any()).Times(1).Return(true)
				mockSup.EXPECT().EnableIPTablesPacketTracing(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = rpcwrapper.EnableIPTablesPacketTracingPayLoad{}

				err := server.EnableIPTablesPacketTracing(rpcwrperreq, &rpcwrperres)

				Convey("Then I should not get an error ", func() {
					So(err, ShouldBeNil)
				})
			})
		})
	})
}
