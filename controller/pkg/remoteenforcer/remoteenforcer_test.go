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

	"github.com/mitchellh/hashstructure"

	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/mockenforcer"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/rpcwrapper/mockrpcwrapper"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/mocksupervisor"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packetprocessor"
	"go.aporeto.io/trireme-lib/controller/pkg/remoteenforcer/internal/statsclient/mockstatsclient"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/policy"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
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

	s, err := secrets.NewCompactPKI(PrivatePEM, PublicPEM, CAPem, Token, constants.CompressionTypeNone)
	if err != nil {
		fmt.Println("CompackPKI creation failed with:", err)
	}
	initEnfPayload.Secrets = s.PublicSecrets()
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
	initFilterQ.NetworkQueuesSynStr = "4:7"
	initFilterQ.NetworkQueuesAckStr = "4:7"
	initFilterQ.NetworkQueuesSynAckStr = "4:7"
	initFilterQ.NetworkQueuesSvcStr = "4:7"
	initFilterQ.ApplicationQueuesSynStr = "0:3"
	initFilterQ.ApplicationQueuesAckStr = "0:3"
	initFilterQ.ApplicationQueuesSvcStr = "0:3"
	initFilterQ.ApplicationQueuesSynAckStr = "0:3"

	return &initFilterQ
}

func initTestSupReqPayload(ctype rpcwrapper.CaptureType) rpcwrapper.InitSupervisorPayload {
	var initSupPayload rpcwrapper.InitSupervisorPayload

	initSupPayload.TriremeNetworks = []string{"127.0.0.1/32 172.0.0.0/8 10.0.0.0/8"}
	initSupPayload.CaptureMethod = ctype

	return initSupPayload
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

func initTestSupPayload() rpcwrapper.SuperviseRequestPayload {

	var initPayload rpcwrapper.SuperviseRequestPayload
	idString := "$namespace=/sibicentos @usr:role=client AporetoContextID=59812ccc27b430000135fbf3"
	anoString := "@sys:name=/nervous_hermann @usr:role=client @usr:vendor=CentOS $id=59812ccc27b430000135fbf3 $namespace=/sibicentos @usr:build-date=20170705 @usr:license=GPLv2 @usr:name=CentOS Base Image $nativecontextid=ac0d3577e808 $operationalstatus=Running role=client $id=59812ccc27b430000135fbf3 $identity=processingunit $namespace=/sibicentos $protected=false $type=Docker @sys:image=centos @usr:role=client $description=centos $enforcerid=598236b81c252c000102665d $name=centos $id=59812ccc27b430000135fbf3 $namespace=/sibicentos"

	initPayload.ContextID = "ac0d3577e808"
	initPayload.Policy = &policy.PUPolicyPublic{
		ManagementID:     "59812ccc27b430000135fbf3",
		TriremeAction:    2,
		IPs:              policy.ExtendedMap{"bridge": "172.17.0.2"},
		Identity:         initIdentity(idString),
		TransmitterRules: initTrans(),
		Annotations:      initAnnotations(anoString),
		TriremeNetworks:  []string{"127.0.0.1/32 172.0.0.0/8 10.0.0.0/8"},
	}

	return initPayload
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
		TriremeNetworks:  []string{"127.0.0.1/32 172.0.0.0/8 10.0.0.0/8"},
	}

	return initPayload
}

func initTestSetTargetPayload() rpcwrapper.SetTargetNetworks {
	var payload rpcwrapper.SetTargetNetworks
	payload.TargetNetworks = []string{"128.0.0.0/1"}
	return payload
}

func initTestUnEnfPayload() rpcwrapper.UnEnforcePayload {

	var initPayload rpcwrapper.UnEnforcePayload

	initPayload.ContextID = "b06f47830f64"

	return initPayload
}

func initTestUnSupPayload() rpcwrapper.UnSupervisePayload {

	var initPayload rpcwrapper.UnSupervisePayload

	initPayload.ContextID = "ac0d3577e808"

	return initPayload
}

func TestNewServer(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to retrieve rpc server handle", t, func() {
		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)

		Convey("Then rpcHdl should resemble rpcwrapper struct", func() {
			So(rpcHdl, ShouldNotBeNil)
		})

		Convey("When I try to create new server with no env set", func() {
			rpcHdl.EXPECT().StartServer(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			var service packetprocessor.PacketProcessor
			pcchan := "/tmp/test.sock"
			secret := "mysecret"
			ctx, cancel := context.WithCancel(context.Background())
			server, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)

			Convey("Then I should get error for no stats", func() {
				So(server, ShouldBeNil)
				So(err, ShouldResemble, errors.New("no path to stats socket provided"))
			})
		})

		Convey("When I try to create new server with env set", func() {
			serr := os.Setenv(constants.EnvStatsChannel, "/tmp/test.sock")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "mysecret")
			So(serr, ShouldBeNil)
			var service packetprocessor.PacketProcessor
			pcchan := os.Getenv(constants.EnvStatsChannel)
			secret := os.Getenv(constants.EnvStatsSecret)
			ctx, cancel := context.WithCancel(context.Background())
			server, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)

			Convey("Then I should get no error", func() {
				So(server, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})
			serr = os.Setenv(constants.EnvStatsChannel, "")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "")
			So(serr, ShouldBeNil)
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

		Convey("Then rpcHdl should resemble rpcwrapper struct", func() {
			So(rpcHdl, ShouldNotBeNil)
		})

		Convey("When I try to create new server with env set", func() {
			serr := os.Setenv(constants.EnvStatsChannel, "/tmp/test.sock")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "T6UYZGcKW-aum_vi-XakafF3vHV7F6x8wdofZs7akGU=")
			So(serr, ShouldBeNil)
			var service packetprocessor.PacketProcessor
			pcchan := os.Getenv(constants.EnvStatsChannel)
			secret := os.Getenv(constants.EnvStatsSecret)
			ctx, cancel := context.WithCancel(context.Background())
			remoteIntf, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, mockStats)
			server, ok := remoteIntf.(*RemoteEnforcer)

			Convey("Then I should get no error", func() {
				So(ok, ShouldBeTrue)
				So(server, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("When I try to initiate an enforcer with invalid secret", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(false)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				digest := hmac.New(sha256.New, []byte("InvalidSecret"))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				rpcwrperreq.HashAuth = []byte{0xC5, 0xD1, 0x24, 0x36, 0x1A, 0xFC, 0x66, 0x3E, 0xAE, 0xD7, 0x68, 0xCE, 0x88, 0x72, 0xC0, 0x97, 0xE4, 0x27, 0x70, 0x6C, 0x47, 0x31, 0x67, 0xEF, 0xD5, 0xCE, 0x73, 0x99, 0x7B, 0xAC, 0x25, 0x94}
				rpcwrperreq.Payload = initTestEnfReqPayload()
				rpcwrperres.Status = ""
				server.enforcer = mockEnf

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldResemble, errors.New("init message authentication failed: not running in a namespace"))
				})
			})

			Convey("When I try to initiate an enforcer", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)
				mockEnf.EXPECT().Run(gomock.Any()).Times(1).Return(nil)
				mockStats.EXPECT().Run(gomock.Any()).Times(1).Return(nil)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				rpcwrperreq.HashAuth = []byte{0xC5, 0xD1, 0x24, 0x36, 0x1A, 0xFC, 0x66, 0x3E, 0xAE, 0xD7, 0x68, 0xCE, 0x88, 0x72, 0xC0, 0x97, 0xE4, 0x27, 0x70, 0x6C, 0x47, 0x31, 0x67, 0xEF, 0xD5, 0xCE, 0x73, 0x99, 0x7B, 0xAC, 0x25, 0x94}
				rpcwrperreq.Payload = initTestEnfReqPayload()
				rpcwrperres.Status = ""
				server.enforcer = mockEnf

				err := server.InitEnforcer(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get no error", func() {
					So(err, ShouldBeNil)
				})
				serr = os.Setenv(constants.EnvStatsChannel, "")
				So(serr, ShouldBeNil)
				serr = os.Setenv(constants.EnvStatsSecret, "")
				So(serr, ShouldBeNil)
			})
		})
	})
}

func TestInitSupervisor(t *testing.T) {

	Convey("When I try to retrieve rpc server handle", t, func() {

		rpcHdl := rpcwrapper.NewRPCServer()
		var rpcWrpper rpcwrapper.RPCWrapper

		Convey("Then rpcHdl should resemble rpcwrapper struct", func() {
			So(rpcHdl, ShouldResemble, &rpcWrpper)
		})

		Convey("When I try to create new server with env set", func() {
			serr := os.Setenv(constants.EnvStatsChannel, "/tmp/test.sock")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "n1KroWMWKP8nJnpWfwSsQu855yvP-ZPaNr-TJFl3gzM=")
			So(serr, ShouldBeNil)
			var service packetprocessor.PacketProcessor
			pcchan := os.Getenv(constants.EnvStatsChannel)
			secret := os.Getenv(constants.EnvStatsSecret)
			ctx, cancel := context.WithCancel(context.Background())
			remoteIntf, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)
			server, ok := remoteIntf.(*RemoteEnforcer)

			Convey("Then I should get no error", func() {
				So(ok, ShouldBeTrue)
				So(server, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("When I try to initiate the supervisor with invalid secret", func() {
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0x47, 0xBE, 0x1A, 0x01, 0x47, 0x4F, 0x4A, 0x7A, 0xB5, 0xDA, 0x97, 0x46, 0xF3, 0x98, 0x50, 0x86, 0xB1, 0xF7, 0x05, 0x65, 0x6F, 0x58, 0x8C, 0x2C, 0x23, 0x9B, 0xA2, 0x82, 0x40, 0x45, 0x24, 0x45}
				rpcwrperreq.Payload = initTestSupReqPayload(rpcwrapper.IPTables)
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte("InvalidSecret"))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				err := server.InitSupervisor(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error for no enforcer", func() {
					So(err, ShouldResemble, errors.New("supervisor init message auth failed"))
				})
			})

			Convey("When I try to initiate the supervisor with IPSets support", func() {
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0x47, 0xBE, 0x1A, 0x01, 0x47, 0x4F, 0x4A, 0x7A, 0xB5, 0xDA, 0x97, 0x46, 0xF3, 0x98, 0x50, 0x86, 0xB1, 0xF7, 0x05, 0x65, 0x6F, 0x58, 0x8C, 0x2C, 0x23, 0x9B, 0xA2, 0x82, 0x40, 0x45, 0x24, 0x45}
				rpcwrperreq.Payload = initTestSupReqPayload(rpcwrapper.IPSets)
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				collector := &collector.DefaultCollector{}
				secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))

				prevRawSocket := nfqdatapath.GetUDPRawSocket
				defer func() {
					nfqdatapath.GetUDPRawSocket = prevRawSocket
				}()
				nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
					return nil, nil
				}

				server.enforcer = enforcer.NewWithDefaults("someServerID", collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"}).(enforcer.Enforcer)

				err := server.InitSupervisor(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error for no IPset support", func() {
					So(err, ShouldResemble, errors.New("ipsets not supported yet"))
				})
			})

			Convey("When I try to initiate the supervisor with no enforcer", func() {
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0x47, 0xBE, 0x1A, 0x01, 0x47, 0x4F, 0x4A, 0x7A, 0xB5, 0xDA, 0x97, 0x46, 0xF3, 0x98, 0x50, 0x86, 0xB1, 0xF7, 0x05, 0x65, 0x6F, 0x58, 0x8C, 0x2C, 0x23, 0x9B, 0xA2, 0x82, 0x40, 0x45, 0x24, 0x45}
				rpcwrperreq.Payload = initTestSupReqPayload(rpcwrapper.IPTables)
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				err := server.InitSupervisor(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error for no enforcer", func() {
					So(err, ShouldNotBeNil)
				})
			})

			Convey("When I try to initiate the supervisor with enforcer", func() {
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0x47, 0xBE, 0x1A, 0x01, 0x47, 0x4F, 0x4A, 0x7A, 0xB5, 0xDA, 0x97, 0x46, 0xF3, 0x98, 0x50, 0x86, 0xB1, 0xF7, 0x05, 0x65, 0x6F, 0x58, 0x8C, 0x2C, 0x23, 0x9B, 0xA2, 0x82, 0x40, 0x45, 0x24, 0x45}
				rpcwrperreq.Payload = initTestSupReqPayload(rpcwrapper.IPTables)
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				collector := &collector.DefaultCollector{}
				secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))

				prevRawSocket := nfqdatapath.GetUDPRawSocket
				defer func() {
					nfqdatapath.GetUDPRawSocket = prevRawSocket
				}()
				nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
					return nil, nil
				}

				server.enforcer = enforcer.NewWithDefaults("someServerID", collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"}).(enforcer.Enforcer)

				err := server.InitSupervisor(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get no error", func() {
					So(err, ShouldBeNil)
				})
			})

			Convey("When I try to initiate the supervisor with another supervisor running", func() {
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0x47, 0xBE, 0x1A, 0x01, 0x47, 0x4F, 0x4A, 0x7A, 0xB5, 0xDA, 0x97, 0x46, 0xF3, 0x98, 0x50, 0x86, 0xB1, 0xF7, 0x05, 0x65, 0x6F, 0x58, 0x8C, 0x2C, 0x23, 0x9B, 0xA2, 0x82, 0x40, 0x45, 0x24, 0x45}
				rpcwrperreq.Payload = initTestSupReqPayload(rpcwrapper.IPTables)
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				collector := &collector.DefaultCollector{}
				secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))

				prevRawSocket := nfqdatapath.GetUDPRawSocket
				defer func() {
					nfqdatapath.GetUDPRawSocket = prevRawSocket
				}()
				nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
					return nil, nil
				}

				server.enforcer = enforcer.NewWithDefaults("someServerID", collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"}).(enforcer.Enforcer)
				server.supervisor, _ = supervisor.NewSupervisor(collector, server.enforcer, constants.RemoteContainer, []string{})

				err := server.InitSupervisor(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get no error", func() {
					So(err, ShouldBeNil)
				})
			})

			serr = os.Setenv(constants.EnvStatsChannel, "")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "")
			So(serr, ShouldBeNil)
		})
	})
}

func TestLaunchRemoteEnforcer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to retrieve rpc server handle", t, func() {
		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)

		Convey("Then rpcHdl should resemble rpcwrapper struct", func() {
			So(rpcHdl, ShouldNotBeNil)
		})

		Convey("When I try to create new server with no env set", func() {
			var service packetprocessor.PacketProcessor
			pcchan := "/tmp/test.sock"
			secret := "mysecret"
			ctx, cancel := context.WithCancel(context.Background())
			server, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)

			Convey("Then I should get error for no stats", func() {
				So(server, ShouldBeNil)
				So(err, ShouldResemble, errors.New("no path to stats socket provided"))
			})
		})

		Convey("When I try to create new server with env set", func() {
			serr := os.Setenv(constants.EnvStatsChannel, "/tmp/test.sock")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "mysecret")
			So(serr, ShouldBeNil)
			var service packetprocessor.PacketProcessor
			pcchan := os.Getenv(constants.EnvStatsChannel)
			secret := os.Getenv(constants.EnvStatsSecret)
			ctx, cancel := context.WithCancel(context.Background())
			remoteIntf, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)
			server, ok := remoteIntf.(*RemoteEnforcer)

			Convey("Then I should get no error", func() {
				So(ok, ShouldBeTrue)
				So(server, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("When I try to start the server", func() {
				serr = os.Setenv(constants.EnvContextSocket, "/tmp/test.sock")
				So(serr, ShouldBeNil)
				envpipe := os.Getenv(constants.EnvContextSocket)
				rpcHdl.EXPECT().StartServer(gomock.Any(), "unix", envpipe, server).Times(1).Return(nil)

				Convey("Then I expect to call start server one time with required parameters", func() {
					err := rpcHdl.StartServer(context.Background(), "unix", envpipe, server)

					Convey("I should not get any error", func() {
						So(err, ShouldBeNil)
					})
				})
			})

			Convey("When I try to exit the enforcer with no enforcer and supervisor", func() {
				server.statsClient = nil
				err := server.EnforcerExit(rpcwrapper.Request{}, &rpcwrapper.Response{})

				Convey("Then I should get no error", func() {
					So(err, ShouldBeNil)
				})
			})

			Convey("When I try to exit the enforcer with supervisor", func() {
				server.statsClient = nil
				c := &collector.DefaultCollector{}
				scrts := secrets.NewPSKSecrets([]byte("test password"))

				prevRawSocket := nfqdatapath.GetUDPRawSocket
				defer func() {
					nfqdatapath.GetUDPRawSocket = prevRawSocket
				}()
				nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
					return nil, nil
				}

				e := enforcer.NewWithDefaults("serverID", c, nil, scrts, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})
				server.supervisor, _ = supervisor.NewSupervisor(c, e, constants.RemoteContainer, []string{})
				server.enforcer = nil
				err := server.EnforcerExit(rpcwrapper.Request{}, &rpcwrapper.Response{})

				Convey("Then I should get no error", func() {
					So(err, ShouldBeNil)
				})
			})
			serr = os.Setenv(constants.EnvStatsChannel, "")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "")
			So(serr, ShouldBeNil)
		})
	})
}

func TestSupervise(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to retrieve rpc server handle", t, func() {
		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)
		mockSup := mocksupervisor.NewMockSupervisor(ctrl)

		Convey("Then rpcHdl should resemble rpcwrapper struct", func() {
			So(rpcHdl, ShouldNotBeNil)
		})

		Convey("When I try to create new server with no env set", func() {
			var service packetprocessor.PacketProcessor
			pcchan := "/tmp/test.sock"
			secret := "mysecret"
			ctx, cancel := context.WithCancel(context.Background())
			server, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)

			Convey("Then I should get error for no stats", func() {
				So(server, ShouldBeNil)
				So(err, ShouldResemble, errors.New("no path to stats socket provided"))
			})
		})

		Convey("When I try to create new server with env set", func() {
			serr := os.Setenv(constants.EnvStatsChannel, "/tmp/test.sock")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "zsGt6jhc1DkE0cHcv8HtJl_iP-8K_zPX4u0TUykDJSg=")
			So(serr, ShouldBeNil)
			var service packetprocessor.PacketProcessor
			pcchan := os.Getenv(constants.EnvStatsChannel)
			secret := os.Getenv(constants.EnvStatsSecret)
			ctx, cancel := context.WithCancel(context.Background())
			remoteIntf, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)
			server, ok := remoteIntf.(*RemoteEnforcer)

			Convey("Then I should get no error", func() {
				So(ok, ShouldBeTrue)
				So(server, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("When I try to send supervise command with invalid secret", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(false)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0x14, 0x5E, 0x0A, 0x3B, 0x50, 0xA3, 0xFF, 0xBC, 0xD5, 0x1B, 0x25, 0x21, 0x7D, 0x32, 0xD2, 0x02, 0x9F, 0x3A, 0xBE, 0xDC, 0x1F, 0xBB, 0xB7, 0x32, 0xFB, 0x91, 0x63, 0xA0, 0xF8, 0xE4, 0x43, 0x80}
				rpcwrperreq.Payload = initTestSupPayload()
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte("InvalidSecret"))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)
				server.supervisor = mockSup

				err := server.Supervise(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldResemble, errors.New("supervise message auth failed"))
				})
			})

			Convey("When I try to send supervise command", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)
				mockSup.EXPECT().Supervise("ac0d3577e808", gomock.Any()).Times(1).Return(nil)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0x14, 0x5E, 0x0A, 0x3B, 0x50, 0xA3, 0xFF, 0xBC, 0xD5, 0x1B, 0x25, 0x21, 0x7D, 0x32, 0xD2, 0x02, 0x9F, 0x3A, 0xBE, 0xDC, 0x1F, 0xBB, 0xB7, 0x32, 0xFB, 0x91, 0x63, 0xA0, 0xF8, 0xE4, 0x43, 0x80}
				rpcwrperreq.Payload = initTestSupPayload()
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)
				server.supervisor = mockSup

				err := server.Supervise(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get no error", func() {
					So(err, ShouldBeNil)
				})
			})
			serr = os.Setenv(constants.EnvStatsChannel, "")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "")
			So(serr, ShouldBeNil)
		})
	})
}

func TestEnforce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to retrieve rpc server handle", t, func() {
		rpcHdl := mockrpcwrapper.NewMockRPCServer(ctrl)
		mockEnf := mockenforcer.NewMockEnforcer(ctrl)

		Convey("Then rpcHdl should resemble rpcwrapper struct", func() {
			So(rpcHdl, ShouldNotBeNil)
		})

		Convey("When I try to create new server with no env set", func() {
			var service packetprocessor.PacketProcessor
			pcchan := "/tmp/test.sock"
			secret := "mysecret"
			ctx, cancel := context.WithCancel(context.Background())
			server, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)

			Convey("Then I should get error for no stats", func() {
				So(server, ShouldBeNil)
				So(err, ShouldResemble, errors.New("no path to stats socket provided"))
			})
		})

		Convey("When I try to create new server with env set", func() {
			serr := os.Setenv(constants.EnvStatsChannel, "/tmp/test.sock")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "KMvm4a6kgLLma5NitOMGx2f9k21G3nrAaLbgA5zNNHM=")
			So(serr, ShouldBeNil)
			var service packetprocessor.PacketProcessor
			pcchan := os.Getenv(constants.EnvStatsChannel)
			secret := os.Getenv(constants.EnvStatsSecret)
			ctx, cancel := context.WithCancel(context.Background())
			remoteIntf, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)
			server, ok := remoteIntf.(*RemoteEnforcer)

			Convey("Then I should get no error", func() {
				So(ok, ShouldBeTrue)
				So(server, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("When I try to send enforce command with invalid secret", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(false)
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
					So(err, ShouldResemble, errors.New("enforce message auth failed"))
				})
			})

			Convey("When I try to send enforce command for local container", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0xDE, 0xBD, 0x1C, 0x6A, 0x2A, 0x51, 0xC0, 0x02, 0x4B, 0xD7, 0xD1, 0x82, 0x78, 0x8A, 0xC4, 0xF1, 0xBE, 0xBF, 0x00, 0x89, 0x47, 0x0F, 0x13, 0x71, 0xAB, 0x4C, 0x0D, 0xD9, 0x9D, 0x85, 0x45, 0x04}
				rpcwrperreq.Payload = initTestEnfPayload()
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				collector := &collector.DefaultCollector{}
				secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))

				prevRawSocket := nfqdatapath.GetUDPRawSocket
				defer func() {
					nfqdatapath.GetUDPRawSocket = prevRawSocket
				}()
				nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
					return nil, nil
				}

				server.enforcer = enforcer.NewWithDefaults("someServerID", collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"}).(enforcer.Enforcer)

				err := server.Enforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldBeNil)
				})
			})

			Convey("When I try to send enforce command for local server", func() {
				rpcHdl.EXPECT().CheckValidity(gomock.Any(), os.Getenv(constants.EnvStatsSecret)).Times(1).Return(true)
				mockEnf.EXPECT().Enforce("b06f47830f64", gomock.Any()).Times(1).Return(nil)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0xDE, 0xBD, 0x1C, 0x6A, 0x2A, 0x51, 0xC0, 0x02, 0x4B, 0xD7, 0xD1, 0x82, 0x78, 0x8A, 0xC4, 0xF1, 0xBE, 0xBF, 0x00, 0x89, 0x47, 0x0F, 0x13, 0x71, 0xAB, 0x4C, 0x0D, 0xD9, 0x9D, 0x85, 0x45, 0x04}
				rpcwrperreq.Payload = initTestEnfPayload()
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)
				server.enforcer = mockEnf

				err := server.Enforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get no error", func() {
					So(err, ShouldBeNil)
				})
			})
			serr = os.Setenv(constants.EnvStatsChannel, "")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "")
			So(serr, ShouldBeNil)
		})
	})
}

func TestUnEnforce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to retrieve rpc server handle", t, func() {
		rpcHdl := rpcwrapper.NewRPCServer()
		mockEnf := mockenforcer.NewMockEnforcer(ctrl)

		Convey("Then rpcHdl should resemble rpcwrapper struct", func() {
			So(rpcHdl, ShouldNotBeNil)
		})

		Convey("When I try to create new server with no env set", func() {
			var service packetprocessor.PacketProcessor
			pcchan := "/tmp/test.sock"
			secret := "mysecret"
			ctx, cancel := context.WithCancel(context.Background())
			server, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)

			Convey("Then I should get error for no stats", func() {
				So(server, ShouldBeNil)
				So(err, ShouldResemble, errors.New("no path to stats socket provided"))
			})
		})

		Convey("When I try to create new server with env set", func() {
			serr := os.Setenv(constants.EnvStatsChannel, "/tmp/test.sock")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "KMvm4a6kgLLma5NitOMGx2f9k21G3nrAaLbgA5zNNHM=")
			So(serr, ShouldBeNil)
			var service packetprocessor.PacketProcessor
			pcchan := os.Getenv(constants.EnvStatsChannel)
			secret := os.Getenv(constants.EnvStatsSecret)
			ctx, cancel := context.WithCancel(context.Background())
			remoteIntf, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)
			server, ok := remoteIntf.(*RemoteEnforcer)

			Convey("Then I should get no error", func() {
				So(ok, ShouldBeTrue)
				So(server, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("When I try to send Unenforce command with invalid secret", func() {
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0xDE, 0xBD, 0x1C, 0x6A, 0x2A, 0x51, 0xC0, 0x02, 0x4B, 0xD7, 0xD1, 0x82, 0x78, 0x8A, 0xC4, 0xF1, 0xBE, 0xBF, 0x00, 0x89, 0x47, 0x0F, 0x13, 0x71, 0xAB, 0x4C, 0x0D, 0xD9, 0x9D, 0x85, 0x45, 0x04}
				rpcwrperreq.Payload = initTestUnEnfPayload()
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte("InvalidSecret"))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				collector := &collector.DefaultCollector{}
				secret := secrets.NewPSKSecrets([]byte("Dummy Test Password"))

				prevRawSocket := nfqdatapath.GetUDPRawSocket
				defer func() {
					nfqdatapath.GetUDPRawSocket = prevRawSocket
				}()
				nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
					return nil, nil
				}

				server.enforcer = enforcer.NewWithDefaults("b06f47830f64", collector, nil, secret, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"}).(enforcer.Enforcer)

				err := server.Unenforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get error", func() {
					So(err, ShouldResemble, errors.New("unenforce message auth failed"))
				})
			})

			Convey("When I try to send Unenforce", func() {
				mockEnf.EXPECT().Unenforce("b06f47830f64").Times(1).Return(nil)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0xDE, 0xBD, 0x1C, 0x6A, 0x2A, 0x51, 0xC0, 0x02, 0x4B, 0xD7, 0xD1, 0x82, 0x78, 0x8A, 0xC4, 0xF1, 0xBE, 0xBF, 0x00, 0x89, 0x47, 0x0F, 0x13, 0x71, 0xAB, 0x4C, 0x0D, 0xD9, 0x9D, 0x85, 0x45, 0x04}
				rpcwrperreq.Payload = initTestUnEnfPayload()
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				server.enforcer = mockEnf
				err := server.Unenforce(rpcwrperreq, &rpcwrperres)

				Convey("Then I should not get any error", func() {
					So(err, ShouldBeNil)
				})
			})
			serr = os.Setenv(constants.EnvStatsChannel, "")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "")
			So(serr, ShouldBeNil)
		})
	})
}

func TestUnSupervise(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	Convey("When I try to retrieve rpc server handle", t, func() {
		rpcHdl := rpcwrapper.NewRPCServer()
		mockSup := mocksupervisor.NewMockSupervisor(ctrl)

		Convey("Then rpcHdl should resemble rpcwrapper struct", func() {
			So(rpcHdl, ShouldNotBeNil)
		})

		Convey("When I try to create new server with no env set", func() {
			var service packetprocessor.PacketProcessor
			pcchan := "/tmp/test.sock"
			secret := "mysecret"
			ctx, cancel := context.WithCancel(context.Background())
			server, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)

			Convey("Then I should get error for no stats", func() {
				So(server, ShouldBeNil)
				So(err, ShouldResemble, errors.New("no path to stats socket provided"))
			})
		})

		Convey("When I try to create new server with env set", func() {
			serr := os.Setenv(constants.EnvStatsChannel, "/tmp/test.sock")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "zsGt6jhc1DkE0cHcv8HtJl_iP-8K_zPX4u0TUykDJSg=")
			So(serr, ShouldBeNil)
			var service packetprocessor.PacketProcessor
			pcchan := os.Getenv(constants.EnvStatsChannel)
			secret := os.Getenv(constants.EnvStatsSecret)
			ctx, cancel := context.WithCancel(context.Background())
			remoteIntf, err := newServer(ctx, cancel, service, rpcHdl, pcchan, secret, nil)
			server, ok := remoteIntf.(*RemoteEnforcer)

			Convey("Then I should get no error", func() {
				So(ok, ShouldBeTrue)
				So(server, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("When I try to send unsupervise command with invalid secret", func() {
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0x14, 0x5E, 0x0A, 0x3B, 0x50, 0xA3, 0xFF, 0xBC, 0xD5, 0x1B, 0x25, 0x21, 0x7D, 0x32, 0xD2, 0x02, 0x9F, 0x3A, 0xBE, 0xDC, 0x1F, 0xBB, 0xB7, 0x32, 0xFB, 0x91, 0x63, 0xA0, 0xF8, 0xE4, 0x43, 0x80}
				rpcwrperreq.Payload = initTestUnSupPayload()
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte("InvalidSecret"))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)

				c := &collector.DefaultCollector{}
				scrts := secrets.NewPSKSecrets([]byte("test password"))

				prevRawSocket := nfqdatapath.GetUDPRawSocket
				defer func() {
					nfqdatapath.GetUDPRawSocket = prevRawSocket
				}()
				nfqdatapath.GetUDPRawSocket = func(mark int, device string) (afinetrawsocket.SocketWriter, error) {
					return nil, nil
				}

				e := enforcer.NewWithDefaults("ac0d3577e808", c, nil, scrts, constants.RemoteContainer, "/proc", []string{"0.0.0.0/0"})

				server.supervisor, _ = supervisor.NewSupervisor(c, e, constants.RemoteContainer, []string{})

				err := server.Unsupervise(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get no error", func() {
					So(err, ShouldResemble, errors.New("unsupervise message auth failed"))
				})
			})

			Convey("When I try to send unsupervise command", func() {
				mockSup.EXPECT().Unsupervise("ac0d3577e808").Times(1).Return(nil)
				var rpcwrperreq rpcwrapper.Request
				var rpcwrperres rpcwrapper.Response

				rpcwrperreq.HashAuth = []byte{0x14, 0x5E, 0x0A, 0x3B, 0x50, 0xA3, 0xFF, 0xBC, 0xD5, 0x1B, 0x25, 0x21, 0x7D, 0x32, 0xD2, 0x02, 0x9F, 0x3A, 0xBE, 0xDC, 0x1F, 0xBB, 0xB7, 0x32, 0xFB, 0x91, 0x63, 0xA0, 0xF8, 0xE4, 0x43, 0x80}
				rpcwrperreq.Payload = initTestUnSupPayload()
				rpcwrperres.Status = ""

				digest := hmac.New(sha256.New, []byte(os.Getenv(constants.EnvStatsSecret)))
				if _, err := digest.Write(getHash(rpcwrperreq.Payload)); err != nil {
					So(err, ShouldBeNil)
				}
				rpcwrperreq.HashAuth = digest.Sum(nil)
				server.supervisor = mockSup

				err := server.Unsupervise(rpcwrperreq, &rpcwrperres)

				Convey("Then I should get no error", func() {
					So(err, ShouldBeNil)
				})
			})
			serr = os.Setenv(constants.EnvStatsChannel, "")
			So(serr, ShouldBeNil)
			serr = os.Setenv(constants.EnvStatsSecret, "")
			So(serr, ShouldBeNil)
		})
	})
}
