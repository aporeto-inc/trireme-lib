// +build !windows

package pucontext

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/nfqdatapath/tokenaccessor"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/ephemeralkeys"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pkiverifier"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets/compactpki"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/crypto"
	"go.aporeto.io/enforcerd/trireme-lib/utils/portspec"
	"go.uber.org/zap"
	"gotest.tools/assert"
)

func Test_NewPU(t *testing.T) {

	Convey("When I call NewPU with proper data", t, func() {

		fp := &policy.PUInfo{
			Runtime: policy.NewPURuntimeWithDefaults(),
			Policy:  policy.NewPUPolicy("", "/xyz", policy.AllowAll, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject, policy.Reject),
		}

		pu, err := NewPU("pu1", fp, nil, 24*time.Hour)

		Convey("I should not get error", func() {
			So(pu, ShouldNotBeNil)
			So(pu.HashID(), ShouldEqual, pu.hashID)
			So(pu.ManagementNamespaceHash(), ShouldEqual, "JJ0iGN3c9I2d+bx4")
			So(pu.Counters(), ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})
}

var (
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
)

func createCompactPKISecrets(tags []string) (ephemeralkeys.KeyAccessor, *x509.Certificate, secrets.Secrets, error) { //nolint
	txtKey, cert, _, err := crypto.LoadAndVerifyECSecrets([]byte(keyPEM), []byte(certPEM), []byte(caPool))
	if err != nil {
		return nil, nil, nil, err
	}

	issuer := pkiverifier.NewPKIIssuer(txtKey)
	txtToken, err := issuer.CreateTokenFromCertificate(cert, tags)
	if err != nil {
		return nil, nil, nil, err
	}

	ControllerInfo := &secrets.ControllerInfo{
		PublicKey: []byte(certPEM),
	}

	tokenKeyPEMs := []*secrets.ControllerInfo{ControllerInfo}

	scrts, err := compactpki.NewCompactPKIWithTokenCA([]byte(keyPEM), []byte(certPEM), []byte(caPool), tokenKeyPEMs, txtToken, claimsheader.CompressionTypeV1)
	if err != nil {
		return nil, nil, nil, err
	}
	keyaccessor, _ := ephemeralkeys.New()
	return keyaccessor, cert, scrts, nil
}

func Test_PUsTokenExchanges(t *testing.T) {
	_, _, scrts, _ := createCompactPKISecrets([]string{"kDMRXWckV9k6mGuJ", "xyz", "eJ1s03u72o6i"})
	ephemeralkeys.UpdateDatapathSecrets(scrts)

	setup := func() (*PUContext, *PUContext) {

		fp := &policy.PUInfo{
			Runtime: policy.NewPURuntimeWithDefaults(),
			Policy:  policy.NewPUPolicy("", "/xyz", policy.AllowAll, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject, policy.Reject),
		}
		ta1, _ := tokenaccessor.New("pu1", 1*time.Hour, nil)
		pu1, _ := NewPU("pu1", fp, ta1, 24*time.Hour)
		pu1.managementID = "1newPU1"
		tags1 := policy.NewTagStore()
		tags1.AppendKeyValue("pu", "pu1")
		pu1.compressedTags = tags1

		ta2, _ := tokenaccessor.New("pu2", 1*time.Hour, nil)
		pu2, _ := NewPU("pu2", fp, ta2, 24*time.Hour)
		pu2.managementID = "1newPU2"
		tags2 := policy.NewTagStore()
		tags2.AppendKeyValue("pu", "pu2")
		pu2.compressedTags = tags2

		return pu1, pu2
	}

	pu1, pu2 := setup()
	token := pu1.createSynToken(nil, claimsheader.NewClaimsHeader())

	claimsOnSynRcvd := &tokens.ConnectionClaims{}
	ka, _ := ephemeralkeys.New()
	secretKey, _, _, remoteNonce, remoteContextID, _, err := pu2.tokenAccessor.ParsePacketToken(ka.PrivateKey(), token.token, scrts, claimsOnSynRcvd, false)

	assert.Equal(t, err, nil, "ParsePacketToken should return nil")
	assert.Equal(t, remoteContextID, pu1.managementID, "ParsePacketToken should get the correct remote contextID")
	tags := claimsOnSynRcvd.CT.GetSlice()
	assert.Equal(t, tags[0], "pu=pu1", "Receiver should receive correct tags")

	ephKeySignV1, _ := pu2.tokenAccessor.Sign(ka.DecodingKeyV1(), scrts.EncodingKey().(*ecdsa.PrivateKey)) //nolint
	ephKeySignV2, _ := pu2.tokenAccessor.Sign(ka.DecodingKeyV2(), scrts.EncodingKey().(*ecdsa.PrivateKey)) //nolint

	claimsOnSynAckSend := &tokens.ConnectionClaims{
		CT:       pu2.CompressedTags(),
		LCL:      remoteNonce,
		RMT:      remoteNonce,
		DEKV1:    ka.DecodingKeyV1(),
		DEKV2:    ka.DecodingKeyV2(),
		SDEKV1:   ephKeySignV1,
		SDEKV2:   ephKeySignV2,
		ID:       pu2.ManagementID(),
		RemoteID: pu1.managementID,
	}

	var encodedBuf [tokens.ClaimsEncodedBufSize]byte
	tokenFromSynAck, _ := pu2.tokenAccessor.CreateSynAckPacketToken(false, claimsOnSynAckSend, encodedBuf[:], remoteNonce, claimsheader.NewClaimsHeader(), scrts, secretKey) //nolint

	claimsOnSynAckRcvd := &tokens.ConnectionClaims{}
	secretKey, _, _, remoteNonce, remoteContextID, _, err = pu1.tokenAccessor.ParsePacketToken(token.privateKey, tokenFromSynAck, scrts, claimsOnSynAckRcvd, true)

	assert.Equal(t, err, nil, "ParsePacketToken should return nil")
	assert.Equal(t, remoteContextID, pu2.managementID, "ParsePacketToken should get the correct remote contextID")
	tags = claimsOnSynAckRcvd.CT.GetSlice()
	assert.Equal(t, tags[0], "pu=pu2", "Receiver should receive correct tags")

	claimsOnAckSend := &tokens.ConnectionClaims{
		ID:       pu1.ManagementID(),
		RMT:      remoteNonce,
		RemoteID: remoteContextID,
	}

	ackToken, _ := pu1.tokenAccessor.CreateAckPacketToken(false, secretKey, claimsOnAckSend, encodedBuf[:])
	claimsOnAckRcvd := &tokens.ConnectionClaims{}
	err = pu2.tokenAccessor.ParseAckToken(false, secretKey, remoteNonce, ackToken, claimsOnAckRcvd)
	assert.Equal(t, err, nil, "error should be nil")
}

func create314SynToken(p *PUContext, claimsHeader *claimsheader.ClaimsHeader) *synTokenInfo {

	var datapathKeyPair ephemeralkeys.KeyAccessor
	var err error
	var nonce []byte

	for {
		datapathKeyPair, err = ephemeralkeys.New()

		if err != nil {
			// can generate errors only when the urandom io read buffer is full. retry till we succeed.
			time.Sleep(10 * time.Millisecond)
			continue
		}

		break
	}

	for {
		// can generate errors only when the urandom io read buffer is full. retry till we succeed.
		nonce, err = crypto.GenerateRandomBytes(16)
		if err != nil {
			continue
		}

		break
	}

	claims := &tokens.ConnectionClaims{
		LCL: nonce,
		CT:  p.CompressedTags(),
		ID:  p.ManagementID(),
	}

	datapathSecret := ephemeralkeys.GetDatapathSecret()
	var encodedBuf [tokens.ClaimsEncodedBufSize]byte

	token, err := p.tokenAccessor.CreateSynPacketToken(claims, encodedBuf[:], nonce, claimsHeader, datapathSecret)
	if err != nil {
		zap.L().Error("Can not create syn packet token", zap.Error(err))
		return nil
	}

	ephKeySignV1, err := p.tokenAccessor.Sign(datapathKeyPair.DecodingKeyV1(), datapathSecret.EncodingKey().(*ecdsa.PrivateKey))
	if err != nil {
		zap.L().Error("Can not sign the ephemeral public key", zap.Error(err))
		return nil
	}

	ephKeySignV2, err := p.tokenAccessor.Sign(datapathKeyPair.DecodingKeyV2(), datapathSecret.EncodingKey().(*ecdsa.PrivateKey))

	if err != nil {
		zap.L().Error("Can not sign the ephemeral public key", zap.Error(err))
		return nil
	}

	privateKey := datapathKeyPair.PrivateKey()
	return &synTokenInfo{datapathSecret: datapathSecret,
		privateKey:      privateKey,
		publicKeyV1:     datapathKeyPair.DecodingKeyV1(),
		publicKeyV2:     datapathKeyPair.DecodingKeyV2(),
		publicKeySignV1: ephKeySignV1,
		publicKeySignV2: ephKeySignV2,
		token:           token}
}

func createV1SynToken(p *PUContext, claimsHeader *claimsheader.ClaimsHeader) *synTokenInfo {
	var datapathKeyPair ephemeralkeys.KeyAccessor
	var err error
	var nonce []byte

	for {
		datapathKeyPair, err = ephemeralkeys.New()

		if err != nil {
			// can generate errors only when the urandom io read buffer is full. retry till we succeed.
			time.Sleep(10 * time.Millisecond)
			continue
		}

		break
	}

	for {
		// can generate errors only when the urandom io read buffer is full. retry till we succeed.
		nonce, err = crypto.GenerateRandomBytes(16)
		if err != nil {
			continue
		}

		break
	}

	claims := &tokens.ConnectionClaims{
		LCL:   nonce,
		DEKV1: datapathKeyPair.DecodingKeyV1(),
		CT:    p.CompressedTags(),
		ID:    p.ManagementID(),
	}

	datapathSecret := ephemeralkeys.GetDatapathSecret()
	var encodedBuf [tokens.ClaimsEncodedBufSize]byte

	token, err := p.tokenAccessor.CreateSynPacketToken(claims, encodedBuf[:], nonce, claimsHeader, datapathSecret)
	if err != nil {
		zap.L().Error("Can not create syn packet token", zap.Error(err))
		return nil
	}

	ephKeySignV1, err := p.tokenAccessor.Sign(datapathKeyPair.DecodingKeyV1(), datapathSecret.EncodingKey().(*ecdsa.PrivateKey))
	if err != nil {
		zap.L().Error("Can not sign the ephemeral public key", zap.Error(err))
		return nil
	}

	if err != nil {
		zap.L().Error("Can not sign the ephemeral public key", zap.Error(err))
		return nil
	}

	privateKey := datapathKeyPair.PrivateKey()
	return &synTokenInfo{datapathSecret: datapathSecret,
		privateKey:      privateKey,
		publicKeyV1:     datapathKeyPair.DecodingKeyV1(),
		publicKeySignV1: ephKeySignV1,
		token:           token}
}

func Test_PUsFrom314To500(t *testing.T) {
	_, _, scrts, _ := createCompactPKISecrets([]string{"kDMRXWckV9k6mGuJ", "xyz", "eJ1s03u72o6i"})
	ephemeralkeys.UpdateDatapathSecrets(scrts)

	setup := func() (*PUContext, *PUContext) {

		fp := &policy.PUInfo{
			Runtime: policy.NewPURuntimeWithDefaults(),
			Policy:  policy.NewPUPolicy("", "/xyz", policy.AllowAll, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject, policy.Reject),
		}
		ta1, _ := tokenaccessor.New("pu1", 1*time.Hour, nil)
		pu1, _ := NewPU("pu1", fp, ta1, 24*time.Hour)
		pu1.managementID = "2newPU1"
		tags1 := policy.NewTagStore()
		tags1.AppendKeyValue("pu", "pu1")
		pu1.compressedTags = tags1

		ta2, _ := tokenaccessor.New("pu2", 1*time.Hour, nil)
		pu2, _ := NewPU("pu2", fp, ta2, 24*time.Hour)
		pu2.managementID = "2newPU2"
		tags2 := policy.NewTagStore()
		tags2.AppendKeyValue("pu", "pu2")
		pu2.compressedTags = tags2

		return pu1, pu2
	}

	pu1, pu2 := setup()
	token := create314SynToken(pu1, claimsheader.NewClaimsHeader())

	claimsOnSynRcvd := &tokens.ConnectionClaims{}
	ka, _ := ephemeralkeys.New()
	secretKey, _, _, remoteNonce, remoteContextID, proto314, err := pu2.tokenAccessor.ParsePacketToken(ka.PrivateKey(), token.token, scrts, claimsOnSynRcvd, false)

	assert.Equal(t, proto314, true, "protocol should be 314")
	assert.Equal(t, err, nil, "ParsePacketToken should return nil")
	assert.Equal(t, remoteContextID, pu1.managementID, "ParsePacketToken should get the correct remote contextID")
	tags := claimsOnSynRcvd.CT.GetSlice()
	assert.Equal(t, tags[0], "pu=pu1", "Receiver should receive correct tags")

	claimsOnSynAckSend := &tokens.ConnectionClaims{
		CT:       pu2.CompressedTags(),
		LCL:      remoteNonce,
		RMT:      remoteNonce,
		ID:       pu2.ManagementID(),
		RemoteID: pu1.managementID,
	}

	var encodedBuf [tokens.ClaimsEncodedBufSize]byte
	tokenFromSynAck, _ := pu2.tokenAccessor.CreateSynAckPacketToken(true, claimsOnSynAckSend, encodedBuf[:], remoteNonce, claimsheader.NewClaimsHeader(), scrts, secretKey) //nolint

	claimsOnSynAckRcvd := &tokens.ConnectionClaims{}
	secretKey, _, _, remoteNonce, remoteContextID, proto314, err = pu1.tokenAccessor.ParsePacketToken(token.privateKey, tokenFromSynAck, scrts, claimsOnSynAckRcvd, true)

	assert.Equal(t, proto314, true, "protocol should be 314")
	assert.Equal(t, err, nil, "ParsePacketToken should return nil")
	assert.Equal(t, remoteContextID, pu2.managementID, "ParsePacketToken should get the correct remote contextID")
	tags = claimsOnSynAckRcvd.CT.GetSlice()
	assert.Equal(t, tags[0], "pu=pu2", "Receiver should receive correct tags")

	claimsOnAckSend := &tokens.ConnectionClaims{
		ID:       pu1.ManagementID(),
		RMT:      remoteNonce,
		RemoteID: remoteContextID,
	}

	ackToken, _ := pu1.tokenAccessor.CreateAckPacketToken(true, secretKey, claimsOnAckSend, encodedBuf[:])
	claimsOnAckRcvd := &tokens.ConnectionClaims{}
	err = pu2.tokenAccessor.ParseAckToken(true, secretKey, remoteNonce, ackToken, claimsOnAckRcvd)
	assert.Equal(t, err, nil, "error should be nil")
}

func Test_PUsFromV1ToV2(t *testing.T) {

	_, _, scrts, _ := createCompactPKISecrets([]string{"kDMRXWckV9k6mGuJ", "xyz", "eJ1s03u72o6i"})
	ephemeralkeys.UpdateDatapathSecrets(scrts)

	setup := func() (*PUContext, *PUContext) {

		fp := &policy.PUInfo{
			Runtime: policy.NewPURuntimeWithDefaults(),
			Policy:  policy.NewPUPolicy("", "/xyz", policy.AllowAll, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject, policy.Reject),
		}
		ta1, _ := tokenaccessor.New("pu1", 1*time.Hour, nil)
		pu1, _ := NewPU("pu1", fp, ta1, 24*time.Hour)
		pu1.managementID = "newPU1"
		tags1 := policy.NewTagStore()
		tags1.AppendKeyValue("pu", "pu1")
		pu1.compressedTags = tags1

		ta2, _ := tokenaccessor.New("pu2", 1*time.Hour, nil)
		pu2, _ := NewPU("pu2", fp, ta2, 24*time.Hour)
		pu2.managementID = "newPU2"
		tags2 := policy.NewTagStore()
		tags2.AppendKeyValue("pu", "pu2")
		pu2.compressedTags = tags2

		return pu1, pu2
	}

	pu1, pu2 := setup()
	token := createV1SynToken(pu1, claimsheader.NewClaimsHeader())

	claimsOnSynRcvd := &tokens.ConnectionClaims{}
	ka, _ := ephemeralkeys.New()
	secretKey, _, _, remoteNonce, remoteContextID, _, err := pu2.tokenAccessor.ParsePacketToken(ka.PrivateKey(), token.token, scrts, claimsOnSynRcvd, false)

	assert.Equal(t, err, nil, "ParsePacketToken should return nil")
	assert.Equal(t, remoteContextID, pu1.managementID, "ParsePacketToken should get the correct remote contextID")
	tags := claimsOnSynRcvd.CT.GetSlice()
	assert.Equal(t, tags[0], "pu=pu1", "Receiver should receive correct tags")

	ephKeySignV1, _ := pu2.tokenAccessor.Sign(ka.DecodingKeyV1(), scrts.EncodingKey().(*ecdsa.PrivateKey)) //nolint

	claimsOnSynAckSend := &tokens.ConnectionClaims{
		CT:       pu2.CompressedTags(),
		LCL:      remoteNonce,
		RMT:      remoteNonce,
		DEKV1:    ka.DecodingKeyV1(),
		SDEKV1:   ephKeySignV1,
		ID:       pu2.ManagementID(),
		RemoteID: pu1.managementID,
	}

	var encodedBuf [tokens.ClaimsEncodedBufSize]byte
	tokenFromSynAck, _ := pu2.tokenAccessor.CreateSynAckPacketToken(false, claimsOnSynAckSend, encodedBuf[:], remoteNonce, claimsheader.NewClaimsHeader(), scrts, secretKey) //nolint

	claimsOnSynAckRcvd := &tokens.ConnectionClaims{}
	secretKey, _, _, remoteNonce, remoteContextID, _, err = pu1.tokenAccessor.ParsePacketToken(token.privateKey, tokenFromSynAck, scrts, claimsOnSynAckRcvd, true)

	assert.Equal(t, err, nil, "ParsePacketToken should return nil")
	assert.Equal(t, remoteContextID, pu2.managementID, "ParsePacketToken should get the correct remote contextID")
	tags = claimsOnSynAckRcvd.CT.GetSlice()
	assert.Equal(t, tags[0], "pu=pu2", "Receiver should receive correct tags")

	claimsOnAckSend := &tokens.ConnectionClaims{
		ID:       pu1.ManagementID(),
		RMT:      remoteNonce,
		RemoteID: remoteContextID,
	}

	ackToken, _ := pu1.tokenAccessor.CreateAckPacketToken(false, secretKey, claimsOnAckSend, encodedBuf[:])
	claimsOnAckRcvd := &tokens.ConnectionClaims{}
	err = pu2.tokenAccessor.ParseAckToken(false, secretKey, remoteNonce, ackToken, claimsOnAckRcvd)
	assert.Equal(t, err, nil, "error should be nil")
}

func Test_PUSearch(t *testing.T) {

	Convey("When I call PU Search", t, func() {

		portRange80, _ := portspec.NewPortSpec(80, 85, nil)
		portRange90, _ := portspec.NewPortSpec(90, 100, nil)

		tagSelectorList := policy.TagSelectorList{
			policy.TagSelector{
				Clause: []policy.KeyValueOperator{
					{
						Key:      "app",
						Value:    []string{"web"},
						ID:       "asfasfasdasd",
						Operator: policy.Equal,
					},
					{
						Key:       "@sys:port",
						Value:     []string{"TCP"},
						ID:        "",
						Operator:  policy.Equal,
						PortRange: portRange80,
					},
				},
				Policy: &policy.FlowPolicy{
					PolicyID: "2",
					Action:   policy.Accept,
				},
			},
			policy.TagSelector{
				Clause: []policy.KeyValueOperator{
					{
						Key:      "app",
						Value:    []string{"web"},
						ID:       "asfasfasdasd",
						Operator: policy.Equal,
					},
					{
						Key:       "@sys:port",
						Value:     []string{"TCP"},
						ID:        "",
						Operator:  policy.Equal,
						PortRange: portRange90,
					},
				},
				Policy: &policy.FlowPolicy{
					PolicyID: "2",
					Action:   policy.Accept,
				},
			},
		}

		d := policy.NewPUPolicy(
			"id",
			"/abc",
			policy.AllowAll,
			nil,
			nil,
			nil,
			nil,
			tagSelectorList,
			nil,
			nil,
			nil,
			nil,
			0,
			0,
			nil,
			nil,
			[]string{},
			policy.EnforcerMapping,
			policy.Reject|policy.Log,
			policy.Reject|policy.Log,
		)

		fp := &policy.PUInfo{
			Runtime: policy.NewPURuntimeWithDefaults(),
			Policy:  d,
		}

		pu, _ := NewPU("pu1", fp, nil, 24*time.Hour)

		tags := policy.NewTagStore()
		tags.AppendKeyValue("app", "web")
		tags.AppendKeyValue(constants.PortNumberLabelString, "TCP/85")

		report, flow := pu.SearchRcvRules(tags)

		Convey("The action should be Accept when port is 85", func() {
			So(flow, ShouldNotBeNil)
			So(report, ShouldNotBeNil)
			So(flow.Action, ShouldEqual, policy.Accept)
			So(report.Action, ShouldEqual, policy.Accept)
			So(flow, ShouldNotBeNil)
		})

		tags = policy.NewTagStore()
		tags.AppendKeyValue("app", "web")
		tags.AppendKeyValue(constants.PortNumberLabelString, "TCP/98")

		report, flow = pu.SearchRcvRules(tags)

		Convey("The action should be Accept when port is 98", func() {
			So(flow, ShouldNotBeNil)
			So(report, ShouldNotBeNil)
			So(flow.Action, ShouldEqual, policy.Accept)
			So(report.Action, ShouldEqual, policy.Accept)
			So(flow, ShouldNotBeNil)
		})

		tags = policy.NewTagStore()
		tags.AppendKeyValue("app", "web")
		tags.AppendKeyValue(constants.PortNumberLabelString, "TCP/101")

		report, flow = pu.SearchRcvRules(tags)

		Convey("The action should be Reject when port is 101", func() {
			So(flow, ShouldNotBeNil)
			So(report, ShouldNotBeNil)
			So(flow.Action, ShouldEqual, policy.Reject|policy.Log)
			So(report.Action, ShouldEqual, policy.Reject|policy.Log)
			So(flow, ShouldNotBeNil)
		})

	})
}
