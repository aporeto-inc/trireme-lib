// +build !windows

package pkitokens

import (
	"context"
	"crypto"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestPKIVerifierValidate(t *testing.T) {

	ctx := context.TODO()
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
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnlK01BDTYbvRBxGM0o3vXNqqvI25
eZ/s3Cq9OXnNpoCI3/DH/tuD3n7cnWcNSfl1qJIH2LVZ0cWUW/L/9i/jPA==
-----END PUBLIC KEY-----
	`)

	// Here are the private keys in case you want to regenerate a new token:
	//
	// -----BEGIN RSA PRIVATE KEY-----
	// MIIEpAIBAAKCAQEAyjDEPJD1Fv1IJIq4mnecoMlSve0vZOTuzDmKuMB4vfBXalKZ
	// gbp4ONL+BvWV9OPs22Smv9SAfnoQ25q8Q9soihzUKhaIAY2CI70ll4exbLK9FD4u
	// Ti1bqn0FdIh04UIyW6s2EqTGMkSKx9THNvAMKx++pPt3US2sQVEC24bWPxRN7RsB
	// BpRjoiEamkA04ioGFhMBbas5MdCLt/fd92aRQCBISOb6PU08fQiARK8g/wdpBUTx
	// y9/Ud1vUnNaZtWm+eLrwdTXgHM3/LG1M4lc0ZqHIL3rMxhae5W+j3SL3ApreiUYu
	// gv/0bCSypvJZjEXKS7SBR/+rtw0/mQpS8DpIkwIDAQABAoIBAQCWkraxfCpp0nn1
	// bLGJp2Ynf4Z1Frvi4XLM+FVMvVmt6dzPu2/CYsHBX6/6Ms5YL51mzZA47+I5TmJb
	// iOKHjiCkqk9+gIUM0vuF7giezljdYEbbWmtVoQXQ84YqgKy6THgAOILuY3OOX+kS
	// ZG1vhlkpjFyHtRXoiKDti40bO1E2a2+O/vpD417hZrezzb97JQ4Cw417jRs3+dpc
	// BaVutFUiIm5HFeVdD0/hqwnYMPeoxxxdj4kiuzI2FZOexPufq9MSrSI0RMnegRGL
	// 8fgg4ZhVuEONtA8eXFI8EpIEhaKOq9CPZuImyKh+Vx4pwcT7NVld70ohqhQaEVqs
	// 6QblHf6hAoGBAOqimWdjGY6PKT6ipF9/6CsNnAAyyG1IRWSLweVDK36DkIxzTKGU
	// fk2uXFw6GlAKu1J0lTfQjxtKoYVljUHjUvfvW9KE/GyuW6eWTxUIrvmpvpcyAV6H
	// gHkt8/A+l8sQS3oMiLJ14c8/W5d4YdB/VBLQHsOi8I5EOGsO7a52fETLAoGBANyZ
	// 3+nq/tyk6hGk+lNJSXnkURydbkONCFhU92iwPC+f/4ILcHdBVjwLOAYa/qUzHvEE
	// H+MtMiuGbDrnjjCytvjmIKmMnJ30BHbXwn0dV+hes1O0EwHoIGtvQyWVH/6zB4ar
	// YkhK9IBtOxfs3ORVeVBoHx/Mq40BAGzGxQQopVpZAoGAScFtCWPMb9SuuWK02tRB
	// Le9sP1+3Qyr5rT6FZ8TykiVXNd80koI0JcUOgWs+RDTrZ2MAWPg1U/XkyiL/AVwt
	// A4T5TzbAhoVUiFymZU1Ce3aRU8PDTGy5xN3eFYIHgyyPHUF9YuPNZLFc4ENWNA0i
	// Z3uGgCbjCUWGmpipvDLAo3sCgYApQEDlvgLAgbofaIlCz76Eo5QjVLEMwq+fzOui
	// 0OnAQhwGVltGgZo9ih+EzMF3ZNLRYOMRmR77kpxke25UXubmLipHajrTMpEvI/OD
	// b9xDYIoKCe9P+Pcu/9Q/j942w4WRwjSTriiAZ2yYcbtwmycfSQkg6iXeLSTGMnke
	// 6PbaqQKBgQDGNwOgdHtMdHyy2kDMLdGKCysEo2eBNAxdRqjGxmsjm6bsd4xyLxS2
	// lkf7v3e9vE24HfBbwMoW4sx1eEDbFc4pai4l4vG3dpbrd3CJa5mpvL3mxGnTlPUy
	// 1PopL5pyjSZ6bcRETolZNM4L8X4jgfwHl3Lvc5jBgQW0PCAVtBVp8g==
	// -----END RSA PRIVATE KEY-----
	//
	// -----BEGIN EC PRIVATE KEY-----
	// MHcCAQEEIBP/5KHpYJ1GwqdOUOCu4+264KP4loONT+9QIzNJwVGjoAoGCCqGSM49
	// AwEHoUQDQgAEnlK01BDTYbvRBxGM0o3vXNqqvI25eZ/s3Cq9OXnNpoCI3/DH/tuD
	// 3n7cnWcNSfl1qJIH2LVZ0cWUW/L/9i/jPA==
	// -----END EC PRIVATE KEY-----
	//
	// And here is the payload data:
	//
	// {
	// 	"sub": "Adam",
	// 	"name": "Eve",
	// 	"admin": true,
	// 	"iat": 1516239022
	// }
	//
	// Go to https://jwt.io/ and
	// - select the right algorithm (RS256 / ES256)
	// - fill in the public key
	// - fill in the private key
	// - ensure the token is still valid (shows Signature Verified)
	// - copy the new token from the encoded section
	//
	validTokenRS256 := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJBZGFtIiwibmFtZSI6IkV2ZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.WHDAmZzmX50GRSXTvB0MqQl2gFHFrQav-v6V2MdbqGXvmBZXus9Bl965Uuqs8uxdJzDad8Is05kC77iHElTasgQZqLwSTN5-WXpZFsW_EOGVcy0puDgREm2QcD8pQeagy6KxwDs0BAQIWwPSfjTCn05w-CRKveo1t0TsKUSMiZltebaZOtAr9etOAwBHIy7QzexrhIzlG6-7fqMbpsNZ8DbanUBc2fiL6Ogs461TQixBDHoRw2HjykGoPRvH3sy8bSRX5l1olBkRb4kic7xSKhiU_YlvmBo9ybC81TRGUtQZl87aLcnv4foDLtFvNAwTyTxfikt2Ka1peKJNgk82Dw"
	validTokenES256 := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJBZGFtIiwibmFtZSI6IkV2ZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.V9HGK6yEZBbjgEsyhQeU6i0Io1KZaCMVgSC0u6fQTRd2TX4Ac-FSDnf44s89PPm8RCHqBATJdJMspIQM66y9Hw"

	// currently unsupported algorithm PS256
	unsupportedTokenPS256 := "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.P9_X1ctIxnnoUpKSWpYw3rF62e-d8LXe3sETuLn4Lhigw5OQhi-mBBKoBMneHy4kimS84zxnMby0FYo9wKM3I3pEg8Qrz0Q00tNhKCwOnZ7Q-e86sW1luK1z82tufF-sZ9_BY_LGQsym0lQmQaHFzLmEDXnOzWsjUThHGVJTI64"

	// supported algorithm but signed with a different key
	invalidTokenRS256 := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"

	Convey("Given a valid PEM", t, func() {

		Convey("it should create a new verifier successfully using NewVerifier()", func() {
			verifier, err := NewVerifier(&PKIJWTVerifier{
				JWTCertPEM: pemBytes,
			})
			So(err, ShouldBeNil)
			So(verifier, ShouldNotBeNil)
			So(len(verifier.keys), ShouldEqual, 2)
		})

		Convey("it should create a new verifier successfully using NewVerifierFromPEM()", func() {
			verifier, err := NewVerifierFromPEM(pemBytes, "", false, false)
			So(err, ShouldBeNil)
			So(verifier, ShouldNotBeNil)
			So(len(verifier.keys), ShouldEqual, 2)
		})
	})

	Convey("Given a verifier with no loaded public keys", t, func() {
		verifier := &PKIJWTVerifier{
			JWTCertPEM: pemBytes,
			keys:       []crypto.PublicKey{},
		}

		Convey("it should fail to validate", func() {
			token := "not empty token"
			_, _, _, err := verifier.Validate(ctx, token)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "No public keys loaded into verifier")
		})
	})

	Convey("Given a valid verifier", t, func() {
		verifier, err := NewVerifierFromPEM(pemBytes, "", false, false)
		So(verifier, ShouldNotBeNil)
		So(err, ShouldBeNil)
		So(len(verifier.keys), ShouldEqual, 2)

		Convey("it should fail to validate an empty token", func() {
			token := ""
			_, _, _, err := verifier.Validate(ctx, token)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Empty token")
		})

		Convey("it should validate a valid RS256 token successfully", func() {
			token := validTokenRS256
			attributes, _, _, err := verifier.Validate(ctx, token)
			So(err, ShouldBeNil)
			So(len(attributes), ShouldBeGreaterThan, 0)
			So(attributes, ShouldContain, "sub=Adam")
			So(attributes, ShouldContain, "name=Eve")
		})

		Convey("it should validate a valid ES256 token successfully", func() {
			token := validTokenES256
			attributes, _, _, err := verifier.Validate(ctx, token)
			So(err, ShouldBeNil)
			So(len(attributes), ShouldBeGreaterThan, 0)
			So(attributes, ShouldContain, "sub=Adam")
			So(attributes, ShouldContain, "name=Eve")
		})

		Convey("it should fail to validate a token signed with an unsupported algorithm", func() {
			token := unsupportedTokenPS256
			_, _, _, err := verifier.Validate(ctx, token)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Invalid token - errors: [unsupported signing method '*jwt.SigningMethodRSAPSS'; unsupported signing method '*jwt.SigningMethodRSAPSS']")
		})

		Convey("it should fail to validate a token signed with an unexpected key", func() {
			token := invalidTokenRS256
			_, _, _, err := verifier.Validate(ctx, token)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "Invalid token - errors: [crypto/rsa: verification error; signing method '*jwt.SigningMethodRSA' and public key type '*ecdsa.PublicKey' mismatch]")
		})
	})
}
