package tcp

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"reflect"
	"testing"

	"go.aporeto.io/enforcerd/trireme-lib/common"
	acommon "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/applicationproxy/common"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

func testTLSCertificate() tls.Certificate {
	certPem := []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func Test_getClientTLSConfig(t *testing.T) {
	type args struct {
		caPool      *x509.CertPool
		clientCerts []tls.Certificate
		serverName  string
		external    bool
	}
	basicCaPool, _ := x509.SystemCertPool()
	basicTLSCert := testTLSCertificate()
	basicTLSCertList := []tls.Certificate{basicTLSCert}
	tests := []struct {
		name    string
		args    args
		wantT   *tls.Config
		wantErr bool
	}{
		{
			name: "basic external service",
			args: args{
				external:    true,
				caPool:      nil,                 // no caPool => we dont need additional CAs to validate server certs. they might be using digicert/letsencrypt/any std cert.
				clientCerts: []tls.Certificate{}, // no certs. for external service dont use client certs
				serverName:  "www.google.com",
			},
			wantT: &tls.Config{
				PreferServerCipherSuites: true,
				SessionTicketsDisabled:   true,
				MaxVersion:               tls.VersionTLS12,
				ServerName:               "www.google.com",
			},
			wantErr: false,
		},
		{
			name: "basic external service ignored client certs",
			args: args{
				external:    true,
				caPool:      nil,              // no caPool => we dont need additional CAs to validate server certs. they might be using digicert/letsencrypt/any std cert.
				clientCerts: basicTLSCertList, // clientCerts should be ignored for external service.
				serverName:  "www.google.com",
			},
			wantT: &tls.Config{
				PreferServerCipherSuites: true,
				SessionTicketsDisabled:   true,
				MaxVersion:               tls.VersionTLS12,
				ServerName:               "www.google.com",
			},
			wantErr: false,
		},
		{
			name: "basic external service with trusted ca pool and ignored cert list",
			args: args{
				caPool:      basicCaPool,      // caPool should be used to validate server certs
				clientCerts: basicTLSCertList, // should be ignored as we dont provide client certs for external service
				serverName:  "www.google.com",
				external:    true,
			},
			wantT: &tls.Config{
				PreferServerCipherSuites: true,
				SessionTicketsDisabled:   true,
				MaxVersion:               tls.VersionTLS12,
				RootCAs:                  basicCaPool,
				ServerName:               "www.google.com",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotT, err := getClientTLSConfig(tt.args.caPool, tt.args.clientCerts, tt.args.serverName, tt.args.external)
			if (err != nil) != tt.wantErr {
				t.Errorf("getClientTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotT, tt.wantT) {
				t.Errorf("getClientTLSConfig() = %+v, want %+v", gotT, tt.wantT)
			}
		})
	}
}

func Test_getTLSServerName(t *testing.T) {
	type args struct {
		addrAndPort string
		service     *policy.ApplicationService
	}
	tests := []struct {
		name     string
		args     args
		wantName string
		wantErr  bool
	}{
		{
			name:     "nil service and bad addr (error)",
			args:     args{},
			wantName: "",
			wantErr:  true,
		},
		{
			name: "service with nil network info and bad addr (error)",
			args: args{
				service: &policy.ApplicationService{},
			},
			wantName: "",
			wantErr:  true,
		},
		{
			name: "no fqdn and bad addr (error)",
			args: args{
				service: &policy.ApplicationService{
					NetworkInfo: &common.Service{
						FQDNs: []string{},
					},
				},
			},
			wantName: "",
			wantErr:  true,
		},
		{
			name: "no fqdn and valid addr (success)",
			args: args{
				addrAndPort: "dns:80",
				service: &policy.ApplicationService{
					NetworkInfo: &common.Service{
						FQDNs: []string{},
					},
				},
			},
			wantName: "dns",
			wantErr:  false,
		},
		{
			name: "fqdn and valid addr use fqdn[0]",
			args: args{
				addrAndPort: "dns:80",
				service: &policy.ApplicationService{
					NetworkInfo: &common.Service{
						FQDNs: []string{"www.google.com", "alt.google.com"},
					},
				},
			},
			wantName: "www.google.com",
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, err := acommon.GetTLSServerName(tt.args.addrAndPort, tt.args.service)
			if (err != nil) != tt.wantErr {
				t.Errorf("getTLSServerName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotName != tt.wantName {
				t.Errorf("getTLSServerName() = %v, want %v", gotName, tt.wantName)
			}
		})
	}
}
