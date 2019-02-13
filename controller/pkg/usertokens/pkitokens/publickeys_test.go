package pkitokens

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestParsePublicKeysFromPEM(t *testing.T) {

	Convey("Given a PEM with a PKIX RSA public key, a PKCS#1 RSA public key and an X509 certificate", t, func() {
		pemBytes := []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyjDEPJD1Fv1IJIq4mnec
oMlSve0vZOTuzDmKuMB4vfBXalKZgbp4ONL+BvWV9OPs22Smv9SAfnoQ25q8Q9so
ihzUKhaIAY2CI70ll4exbLK9FD4uTi1bqn0FdIh04UIyW6s2EqTGMkSKx9THNvAM
Kx++pPt3US2sQVEC24bWPxRN7RsBBpRjoiEamkA04ioGFhMBbas5MdCLt/fd92aR
QCBISOb6PU08fQiARK8g/wdpBUTxy9/Ud1vUnNaZtWm+eLrwdTXgHM3/LG1M4lc0
ZqHIL3rMxhae5W+j3SL3ApreiUYugv/0bCSypvJZjEXKS7SBR/+rtw0/mQpS8DpI
kwIDAQAB
-----END PUBLIC KEY-----
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyjDEPJD1Fv1IJIq4mnecoMlSve0vZOTuzDmKuMB4vfBXalKZgbp4
ONL+BvWV9OPs22Smv9SAfnoQ25q8Q9soihzUKhaIAY2CI70ll4exbLK9FD4uTi1b
qn0FdIh04UIyW6s2EqTGMkSKx9THNvAMKx++pPt3US2sQVEC24bWPxRN7RsBBpRj
oiEamkA04ioGFhMBbas5MdCLt/fd92aRQCBISOb6PU08fQiARK8g/wdpBUTxy9/U
d1vUnNaZtWm+eLrwdTXgHM3/LG1M4lc0ZqHIL3rMxhae5W+j3SL3ApreiUYugv/0
bCSypvJZjEXKS7SBR/+rtw0/mQpS8DpIkwIDAQAB
-----END RSA PUBLIC KEY-----
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUTBdVdOoTt+z1c+25X1WdKLEqc/IwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xOTAxMzEwNTE4MDVaFw0yOTAx
MjgwNTE4MDVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDKMMQ8kPUW/Ugkiriad5ygyVK97S9k5O7MOYq4wHi9
8FdqUpmBung40v4G9ZX04+zbZKa/1IB+ehDbmrxD2yiKHNQqFogBjYIjvSWXh7Fs
sr0UPi5OLVuqfQV0iHThQjJbqzYSpMYyRIrH1Mc28AwrH76k+3dRLaxBUQLbhtY/
FE3tGwEGlGOiIRqaQDTiKgYWEwFtqzkx0Iu39933ZpFAIEhI5vo9TTx9CIBEryD/
B2kFRPHL39R3W9Sc1pm1ab54uvB1NeAczf8sbUziVzRmocgveszGFp7lb6PdIvcC
mt6JRi6C//RsJLKm8lmMRcpLtIFH/6u3DT+ZClLwOkiTAgMBAAGjUzBRMB0GA1Ud
DgQWBBRzt5Gi91WRLBU1PRlo/wCC44DNnzAfBgNVHSMEGDAWgBRzt5Gi91WRLBU1
PRlo/wCC44DNnzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAv
+NayVYU//8QX2TIQ5CcH/3iOCOa9Qx4KHYtyv+/ElBm2WaWRbJiy470D/I2tjkO0
J4a0kihMKEkwAVUvskbM+PjTcrgaE205YO/Pyn00s0Xt3yBp2Cf6rmcNtda4hqCs
ZNhCEXxAXbLxGb5oXd+Wis/tzpBNYrw9x9r3Axr9U2pW+sSzXsUqRdBvaHpywIRq
6FnpawXPJMIOaMohmWAPYnmqILUs0CslzmXQypayslAFC2adr1NQPwZw0FJ3UIQM
AyfixuFuZbOVlwm/zJqX0G0NbitPybGV5XneC89OF90H0zfv47Us0akzyY6yGLp/
+3ASkOBz0ypQ6pgZK/kj
-----END CERTIFICATE-----
		`)

		Convey("then parsePublicKeysFromPEM should return 3 public keys", func() {
			keys, err := parsePublicKeysFromPEM(pemBytes)
			So(err, ShouldBeNil)
			So(len(keys), ShouldEqual, 3)
		})
	})

	Convey("Given a PEM with an RSA private key and a DSA public key", t, func() {
		pemBytes := []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyjDEPJD1Fv1IJIq4mnecoMlSve0vZOTuzDmKuMB4vfBXalKZ
gbp4ONL+BvWV9OPs22Smv9SAfnoQ25q8Q9soihzUKhaIAY2CI70ll4exbLK9FD4u
Ti1bqn0FdIh04UIyW6s2EqTGMkSKx9THNvAMKx++pPt3US2sQVEC24bWPxRN7RsB
BpRjoiEamkA04ioGFhMBbas5MdCLt/fd92aRQCBISOb6PU08fQiARK8g/wdpBUTx
y9/Ud1vUnNaZtWm+eLrwdTXgHM3/LG1M4lc0ZqHIL3rMxhae5W+j3SL3ApreiUYu
gv/0bCSypvJZjEXKS7SBR/+rtw0/mQpS8DpIkwIDAQABAoIBAQCWkraxfCpp0nn1
bLGJp2Ynf4Z1Frvi4XLM+FVMvVmt6dzPu2/CYsHBX6/6Ms5YL51mzZA47+I5TmJb
iOKHjiCkqk9+gIUM0vuF7giezljdYEbbWmtVoQXQ84YqgKy6THgAOILuY3OOX+kS
ZG1vhlkpjFyHtRXoiKDti40bO1E2a2+O/vpD417hZrezzb97JQ4Cw417jRs3+dpc
BaVutFUiIm5HFeVdD0/hqwnYMPeoxxxdj4kiuzI2FZOexPufq9MSrSI0RMnegRGL
8fgg4ZhVuEONtA8eXFI8EpIEhaKOq9CPZuImyKh+Vx4pwcT7NVld70ohqhQaEVqs
6QblHf6hAoGBAOqimWdjGY6PKT6ipF9/6CsNnAAyyG1IRWSLweVDK36DkIxzTKGU
fk2uXFw6GlAKu1J0lTfQjxtKoYVljUHjUvfvW9KE/GyuW6eWTxUIrvmpvpcyAV6H
gHkt8/A+l8sQS3oMiLJ14c8/W5d4YdB/VBLQHsOi8I5EOGsO7a52fETLAoGBANyZ
3+nq/tyk6hGk+lNJSXnkURydbkONCFhU92iwPC+f/4ILcHdBVjwLOAYa/qUzHvEE
H+MtMiuGbDrnjjCytvjmIKmMnJ30BHbXwn0dV+hes1O0EwHoIGtvQyWVH/6zB4ar
YkhK9IBtOxfs3ORVeVBoHx/Mq40BAGzGxQQopVpZAoGAScFtCWPMb9SuuWK02tRB
Le9sP1+3Qyr5rT6FZ8TykiVXNd80koI0JcUOgWs+RDTrZ2MAWPg1U/XkyiL/AVwt
A4T5TzbAhoVUiFymZU1Ce3aRU8PDTGy5xN3eFYIHgyyPHUF9YuPNZLFc4ENWNA0i
Z3uGgCbjCUWGmpipvDLAo3sCgYApQEDlvgLAgbofaIlCz76Eo5QjVLEMwq+fzOui
0OnAQhwGVltGgZo9ih+EzMF3ZNLRYOMRmR77kpxke25UXubmLipHajrTMpEvI/OD
b9xDYIoKCe9P+Pcu/9Q/j942w4WRwjSTriiAZ2yYcbtwmycfSQkg6iXeLSTGMnke
6PbaqQKBgQDGNwOgdHtMdHyy2kDMLdGKCysEo2eBNAxdRqjGxmsjm6bsd4xyLxS2
lkf7v3e9vE24HfBbwMoW4sx1eEDbFc4pai4l4vG3dpbrd3CJa5mpvL3mxGnTlPUy
1PopL5pyjSZ6bcRETolZNM4L8X4jgfwHl3Lvc5jBgQW0PCAVtBVp8g==
-----END RSA PRIVATE KEY-----
		`)

		Convey("then parsePublicKeysFromPEM should return with an error", func() {
			keys, err := parsePublicKeysFromPEM(pemBytes)
			So(keys, ShouldBeNil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "no valid certificates or public keys found (errors: [unsupported PEM type RSA PRIVATE KEY])")
		})
	})

	Convey("Given a PEM with a valid ECDSA and RSA public key, and a DSA public key and an invalid PKCS#1 RSA public key", t, func() {
		pemBytes := []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnlK01BDTYbvRBxGM0o3vXNqqvI25
eZ/s3Cq9OXnNpoCI3/DH/tuD3n7cnWcNSfl1qJIH2LVZ0cWUW/L/9i/jPA==
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyjDEPJD1Fv1IJIq4mnec
oMlSve0vZOTuzDmKuMB4vfBXalKZgbp4ONL+BvWV9OPs22Smv9SAfnoQ25q8Q9so
ihzUKhaIAY2CI70ll4exbLK9FD4uTi1bqn0FdIh04UIyW6s2EqTGMkSKx9THNvAM
Kx++pPt3US2sQVEC24bWPxRN7RsBBpRjoiEamkA04ioGFhMBbas5MdCLt/fd92aR
QCBISOb6PU08fQiARK8g/wdpBUTxy9/Ud1vUnNaZtWm+eLrwdTXgHM3/LG1M4lc0
ZqHIL3rMxhae5W+j3SL3ApreiUYugv/0bCSypvJZjEXKS7SBR/+rtw0/mQpS8DpI
kwIDAQAB
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MIIDSDCCAjoGByqGSM44BAEwggItAoIBAQCsVBV4gVV/zdmxWu8cU95vxY5D2RVG
n6r56BOmnBF6beLZJKIK17FsurubePRfhLiVSk/RIA3aECPe8kRdRYAR23daCptw
THaZMZ0s2mNQfJEc6sXCE3/EVlPPEZqvm7RilYxb1PNZY55X7EzMhhBc1zRiSQck
Va8qDHP98vvZjd4G9W+aF2UOMQko9iN6hTjFkUgmNhqIHS3UAoANQ3y2sYHXZZuq
EP9EKk8EQ5wv4w73eFJXj84pN6L3VvhLjq1Akjk/gl2p7w8cCdXzcfKBD7qXQZZr
Qt4Pmz/BQu6wr4QBX3FiIghUZULlnCjhFNIrXTYbOskK/XGg62aV7Qn5AiEA6hP4
cBgclv0kO5Qyg3qLVwMWOO1e4opX6EbqmK+kXysCggEBAIF77NYg4ttsGG2OiIs2
yVBsV4w7EORIC+lG2+ZzVRSHm3QtNPeLoN6PwDtagpER2pUyjpXuxOcgE47hSUCQ
RpSjXGtj22WbKjXZ2p8mkTScFvA2btgR+O4Nx0f0eShCz1fkrt8BaKRumzrzgoNI
mcAuVOVqLLl4VkOXwsGvuH5cBVhW1sNKDc3VMYTsh34MDSJJEutFZeCokYwd6wo2
pYVdXsDmc7uhPRK3YhtBV3lrXIehNlIukyO7li+wKU7SLyneBY/huBzYrw1JBDWK
1CHqRDJm38yzpEOKhu3gefR+j1BZqev9O2tsbFJe3F/cYV1hDWR8jsZz+gfDUXja
z9oDggEGAAKCAQEAoIbxish+OZADAwMJRP8nGYVIfSkWBXvC96nfQG4tZtqB4Z14
cjOyChnMuHlQnDIWYhVVmDiIHJFGtsHUb8iPGqbpGeEmScWG4HsSnsNAK/dOKVTE
OxGaq/3+Lisg8uyTqzAR5W5OdFlCw3qhzYG6G7kHNxGicN5qLQILTQeHIJiuioiE
oDhpga7IB8pGNsXHpO40KeFe2BaZBpKnCQUF32kMnEFP9AqYnZ/io2vhCViee+O3
A5/Wjke753qo+HUPj7C41wUwvXbXNfkGpXE4nyJZb37Ed+IMQu3sE/X6A2Vgbl+F
2mpfWPo/ZC23fGe4ExyTKsD+hRIP2LlxhWI1xw==
-----END PUBLIC KEY-----
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyjDEPJD1Fv1IJIq4mnec
oMlSve0vZOTuzDmKuMB4vfBXalKZgbp4ONL+BvWV9OPs22Smv9SAfnoQ25q8Q9so
ihzUKhaIAY2CI70ll4exbLK9FD4uTi1bqn0FdIh04UIyW6s2EqTGMkSKx9THNvAM
Kx++pPt3US2sQVEC24bWPxRN7RsBBpRjoiEamkA04ioGFhMBbas5MdCLt/fd92aR
QCBISOb6PU08fQiARK8g/wdpBUTxy9/Ud1vUnNaZtWm+eLrwdTXgHM3/LG1M4lc0
ZqHIL3rMxhae5W+j3SL3ApreiUYugv/0bCSypvJZjEXKS7SBR/+rtw0/mQpS8DpI
kwIDAQAB
-----END RSA PUBLIC KEY-----
		`)

		Convey("then parsePublicKeysFromPEM should return with an error", func() {
			keys, err := parsePublicKeysFromPEM(pemBytes)
			So(keys, ShouldNotBeNil)
			So(err, ShouldNotBeNil)
			So(len(keys), ShouldEqual, 2)
			So(err.Error(), ShouldEqual, "[unsupported key type *dsa.PublicKey; asn1: structure error: tags don't match (2 vs {class:0 tag:16 length:13 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false}  @2]")
			So(keys[0], ShouldHaveSameTypeAs, &ecdsa.PublicKey{})
			So(keys[1], ShouldHaveSameTypeAs, &rsa.PublicKey{})
		})
	})
}
