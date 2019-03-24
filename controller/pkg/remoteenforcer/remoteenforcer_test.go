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

	"github.com/golang/mock/gomock"
	"github.com/mitchellh/hashstructure"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/mockenforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/mocksupervisor"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/debugclient/mockdebugclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statsclient/mockstatsclient"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statscollector/mockstatscollector"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

const (
	PrivatePEMStr = `-----BEGIN EC PRIVATE KEY----- 
MHcCAQEEICtUSeD3huL6YqL1ffZczlVg9MxAjplXtsoSRvnXIr2uoAoGCCqGSM49
AwEHoUQDQgAEuDv6jIPALmJ5VHwHEdmU4fL0c94jLq9KXHPCaa8Bh0MP8VekxsLr
zhJwGTIppOHzzY3+s6ltYhw8folYdY6aGQ==
-----END EC PRIVATE KEY-----`
	PublicPEMStr = `-----BEGIN CERTIFICATE-----
MIIB/DCCAaGgAwIBAgIRAMMNe+keB1SxcRtLQcH0e8AwCgYIKoZIzj0EAwIwJDEi
MCAGA1UEAxMZc2FuZGJveCBQdWJsaWMgU2lnbmluZyBDQTAeFw0xODA4MDIyMTE1
NDRaFw0xOTA3MDUwNDE1NDRaMFYxDjAMBgNVBAoTBXZhcnVuMRowGAYDVQQLExFh
cG9yZXRvLWVuZm9yY2VyZDEoMCYGA1UEAwwfNWI2MzgyOTBlNTQ2NDQwMDAxMTA3
YTYyQC92YXJ1bjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLg7+oyDwC5ieVR8
BxHZlOHy9HPeIy6vSlxzwmmvAYdDD/FXpMbC684ScBkyKaTh882N/rOpbWIcPH6J
WHWOmhmjgYEwfzAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwQAYDVR0RBDkwN4IJbG9jYWxob3N0ghJh
cG9tdXgtZW5mb3JjZXJkLTGHBH8AAAGHBAoAAg+HBMCoZGSHBKwRAAEwCgYIKoZI
zj0EAwIDSQAwRgIhAOkFQCtr+hJqX1/eEgqmcm9seUxEhMd+DAQhdZ7MEfLCAiEA
3OQYX56J+kI4CGSTgeNAwfQLnMqXOhe9g5utmhdGvVU=
-----END CERTIFICATE-----`
	CAPemStr = `-----BEGIN CERTIFICATE-----
MIIBZzCCAQ2gAwIBAgIQJrc9ZSvd4pnvE/voxTzfOTAKBggqhkjOPQQDAjAiMSAw
HgYDVQQDExdzYW5kYm94IEludGVybWVkaWF0ZSBDQTAeFw0xODAyMTMyMzIyMTVa
Fw0yNzEyMjMyMzIyMTVaMCQxIjAgBgNVBAMTGXNhbmRib3ggUHVibGljIFNpZ25p
bmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQLvqsFWmDZ4w5XazDGcQRL
EU3J8yGjMwAXPfOb6/YCZJvV7szGwZ2MzgJz0ZN+yTwO6m4Bzi326sgLq6Ep1b26
oyMwITAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD
AgNIADBFAiBmdiNzm6ESfJq6F3EKzDZshMZf2FfhtMWEjXsBJk4L+wIhAJKgcEIP
uy3y3dXDc98UvqO+8mwL0uL/WZAZm04gxvmL
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBXTCCAQOgAwIBAgIQZ8FSoHZ7t2uG7wXIlRdCRDAKBggqhkjOPQQDAjAaMRgw
FgYDVQQDEw9zYW5kYm94IFJvb3QgQ0EwHhcNMTgwMjEzMjMyMjE1WhcNMjcxMjIz
MjMyMjE1WjAiMSAwHgYDVQQDExdzYW5kYm94IEludGVybWVkaWF0ZSBDQTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABL/tmEjLV1s/F11Euv2PLSk/nBfmZeNecaJh
UiJg6OG2ARLkZsKy1j21w55WXyMoZWywxkZevWvq139QmAzDGQejIzAhMA4GA1Ud
DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIEGM
5IgEg4vmJdzAfCv+9eeaEME8Uxqrvaj2lhi7lR6CAiEAtxh30DvlupzqkNE9Wf8C
PmH3tlujG+hMEVWkWb4iB+o=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBVDCB+6ADAgECAhAGLATWHLVM8ACWNwvNTMyHMAoGCCqGSM49BAMCMBoxGDAW
BgNVBAMTD3NhbmRib3ggUm9vdCBDQTAeFw0xODAyMTMyMzIyMTVaFw0yNzEyMjMy
MzIyMTVaMBoxGDAWBgNVBAMTD3NhbmRib3ggUm9vdCBDQTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABHfpqTOD/fA1IQrueLpwF0DiomEPhSJ4M9ATXDGredVbPjoL
tzKZxpiDRlreCGy19//70CPCFaIOo8c37f/PkzCjIzAhMA4GA1UdDwEB/wQEAwIB
BjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCkDmsb3XVAarvo
rbC83pJYJv7xXgCOr8qHdL5KnSoCuwIgLt75v8+/p/qrniv4ob4rneyovT4G0FbO
mGWH5/94d5k=
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

	dur, _ := time.ParseDuration("8760h0m0s")
	initEnfPayload.Validity = dur
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
		statsClient := mockstatsclient.NewMockStatsClient(ctrl)
		debugClient := mockdebugclient.NewMockDebugClient(ctrl)
		collector := mockstatscollector.NewMockCollector(ctrl)

		Convey("When I try to create new server with no env set", func() {
			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			rpcHdl.EXPECT().StartServer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

			server, err := newRemoteEnforcer(ctx, cancel, nil, rpcHdl, "mysecret", statsClient, collector, debugClient)

			Convey("Then I should get error for no stats", func() {
				So(err, ShouldBeNil)
				So(server, ShouldNotBeNil)
				So(server.service, ShouldBeNil)
				So(server.rpcHandle, ShouldEqual, rpcHdl)
				So(server.procMountPoint, ShouldResemble, constants.DefaultProcMountPoint)
				So(server.statsClient, ShouldEqual, statsClient)
				So(server.debugClient, ShouldEqual, debugClient)
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
		mockStats := mockstatsclient.NewMockStatsClient(ctrl)
		mockDebugClient := mockdebugclient.NewMockDebugClient(ctrl)
		mockCollector := mockstatscollector.NewMockCollector(ctrl)
		mockSupevisor := mocksupervisor.NewMockSupervisor(ctrl)

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
		) (enforcer.Enforcer, error) {
			return mockEnf, nil
		}

		createSupervisor = func(
			collector collector.EventCollector,
			enforcerInstance enforcer.Enforcer,
			mode constants.ModeType,
			cfg *runtime.Configuration,
			p packetprocessor.PacketProcessor,
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
			server, err := newRemoteEnforcer(ctx, cancel, service, rpcHdl, secret, mockStats, mockCollector, mockDebugClient)
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

			Convey("When I try to instantiate the enforcer and the debug client fails to run, it should clean up", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)

				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.Payload = initTestEnfReqPayload()

				mockEnf.EXPECT().Run(server.ctx).Return(nil)
				mockStats.EXPECT().Run(server.ctx).Return(nil)
				mockSupevisor.EXPECT().Run(server.ctx).Return(nil)
				mockDebugClient.EXPECT().Run(server.ctx).Return(fmt.Errorf("debug error"))
				mockSupevisor.EXPECT().CleanUp()
				mockEnf.EXPECT().CleanUp()

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldNotBeNil)
					So(err, ShouldResemble, errors.New("DebugClientdebug error"))
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
				mockDebugClient.EXPECT().Run(server.ctx).Return(nil)

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
		mockStats := mockstatsclient.NewMockStatsClient(ctrl)
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
				mockStats.EXPECT().SendStats()
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
				mockStats.EXPECT().SendStats()
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
				mockStats.EXPECT().SendStats()
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
				mockStats.EXPECT().SendStats()
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
				mockEnf.EXPECT().EnableDatapathPacketTracing(gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("error"))

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
				mockEnf.EXPECT().EnableDatapathPacketTracing(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

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
