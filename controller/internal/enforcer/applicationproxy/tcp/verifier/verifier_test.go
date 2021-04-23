package verifier

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

func Test_verifier_TrustCAs(t *testing.T) {
	type fields struct {
		trustedCAPool *x509.CertPool
	}
	type args struct {
		caPool *x509.CertPool
	}
	sysPool, err := x509.SystemCertPool()
	if err != nil {
		t.Errorf("unable to get system certs")
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			"basic nil",
			fields{
				trustedCAPool: nil,
			},
			args{
				caPool: nil,
			},
		},
		{
			"basic valid",
			fields{
				trustedCAPool: sysPool,
			},
			args{
				caPool: sysPool,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &verifier{
				trustedCAPool: tt.fields.trustedCAPool,
			}
			v.TrustCAs(tt.args.caPool)
			if v.trustedCAPool != tt.args.caPool {
				t.Errorf("ca pool not appropriately setup")
			}
		})
	}
}

// Dummy PolicyLookup implementer to test
type policyReporter struct {
	ip    int
	ipret bool
	id    int
	idret bool
}

func (p *policyReporter) IDLookup(remoteController, remotePUID string, tags *policy.TagStore) bool {
	p.id++
	return p.idret
}
func (p *policyReporter) IPLookup() bool {
	p.ip++
	return p.ipret
}

func (p *policyReporter) ReportStats(remoteType collector.EndPointType, remoteController string, remotePUID string, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy, accept bool) {

}

func (p *policyReporter) Policy(tags *policy.TagStore) (*policy.FlowPolicy, *policy.FlowPolicy) {
	return nil, nil
}

func Test_verifier_VerifyPeerCertificate(t *testing.T) {
	type fields struct {
		trustedCAs *x509.CertPool
	}
	type args struct {
		rawCerts             [][]byte
		verifiedChains       [][]*x509.Certificate
		policyReporter       *policyReporter
		mustHaveClientIDCert bool
	}
	type want struct {
		err     bool
		ipCount int
		idCount int
	}

	// Aporeto CA Root
	certs, err := ioutil.ReadFile("./testdata/myca-cert.pem")
	if err != nil {
		panic("unable to load CA")
	}
	block, _ := pem.Decode(certs)
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	aporetoCertRoot, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	aporetoCAPool := x509.NewCertPool()
	if ok := aporetoCAPool.AppendCertsFromPEM(certs); !ok {
		panic("unable to append CA to root")
	}

	// Aporeto Client Bad Cert Leaf with Tags
	certs, err = ioutil.ReadFile("./testdata/myclient-bad-cert.pem")
	if err != nil {
		panic("unable to load client bad cert")
	}
	block, _ = pem.Decode(certs)
	if block == nil {
		panic("failed to parse client bad certificate PEM")
	}
	aporetoClientBadCertWithExtension, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse client bad certificate: " + err.Error())
	}

	// Aporeto Client IP Cert Leaf with Tags
	certs, err = ioutil.ReadFile("./testdata/myclient-ip-cert.pem")
	if err != nil {
		panic("unable to load client ip cert")
	}
	block, _ = pem.Decode(certs)
	if block == nil {
		panic("failed to parse client ip certificate PEM")
	}
	aporetoClientIPCertWithExtension, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse client ip certificate: " + err.Error())
	}

	// Aporeto Client DNS Cert Leaf with Tags
	certs, err = ioutil.ReadFile("./testdata/myclient-dns-cert.pem")
	if err != nil {
		panic("unable to load client dns cert")
	}
	block, _ = pem.Decode(certs)
	if block == nil {
		panic("failed to parse client dns certificate PEM")
	}
	aporetoClientDNSCertWithExtension, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse client dns certificate: " + err.Error())
	}

	// Aporeto Server Cert Leaf with Tags
	certs, err = ioutil.ReadFile("./testdata/myserver-cert.pem")
	if err != nil {
		panic("unable to load server cert")
	}
	block, _ = pem.Decode(certs)
	if block == nil {
		panic("failed to parse server certificate PEM")
	}
	aporetoServerCertWithExtension, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse server certificate: " + err.Error())
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name:   "ip lookup - success (no aporeto tags)",
			fields: fields{},
			args: args{
				policyReporter: &policyReporter{
					ipret: true,
					idret: true,
				},
			},
			want: want{
				err:     false,
				ipCount: 1,
				idCount: 0,
			},
		},
		{
			name:   "ip lookup - failure (no aporeto tags)",
			fields: fields{},
			args: args{
				policyReporter: &policyReporter{
					ipret: false,
					idret: false,
				},
			},
			want: want{
				err:     true,
				ipCount: 1,
				idCount: 0,
			},
		},
		{
			name: "ip lookup - success (no trusted CAs)",
			fields: fields{
				trustedCAs: x509.NewCertPool(),
			},
			args: args{
				verifiedChains: [][]*x509.Certificate{
					{
						aporetoClientIPCertWithExtension,
						aporetoCertRoot,
					},
				},
				policyReporter: &policyReporter{
					ipret: true,
					idret: true,
				},
			},
			want: want{
				err:     false,
				ipCount: 1,
				idCount: 0,
			},
		},
		{
			name:   "ip lookup - success (missing chain in trusted CAs)",
			fields: fields{},
			args: args{
				verifiedChains: [][]*x509.Certificate{
					{
						aporetoClientIPCertWithExtension,
					},
				},
				policyReporter: &policyReporter{
					ipret: true,
					idret: true,
				},
			},
			want: want{
				err:     false,
				ipCount: 1,
				idCount: 0,
			},
		},
		{
			name: "ip lookup - success (missing aporeto tags in verified chain)",
			fields: fields{
				trustedCAs: aporetoCAPool,
			},
			args: args{
				verifiedChains: [][]*x509.Certificate{
					{
						aporetoCertRoot,
					},
				},
				policyReporter: &policyReporter{
					ipret: true,
					idret: true,
				},
			},
			want: want{
				err:     false,
				ipCount: 1,
				idCount: 0,
			},
		},
		{
			name: "id lookup (client Bad) - failure",
			fields: fields{
				trustedCAs: aporetoCAPool,
			},
			args: args{
				verifiedChains: [][]*x509.Certificate{
					{
						aporetoClientBadCertWithExtension,
						aporetoCertRoot,
					},
				},
				policyReporter: &policyReporter{
					ipret: true,
					idret: true,
				},
				mustHaveClientIDCert: true,
			},
			want: want{
				err:     true,
				ipCount: 0,
				idCount: 0,
			},
		},
		{
			name: "id lookup (client IP) - success",
			fields: fields{
				trustedCAs: aporetoCAPool,
			},
			args: args{
				verifiedChains: [][]*x509.Certificate{
					{
						aporetoClientIPCertWithExtension,
						aporetoCertRoot,
					},
				},
				policyReporter: &policyReporter{
					ipret: true,
					idret: true,
				},
			},
			want: want{
				err:     false,
				ipCount: 0,
				idCount: 1,
			},
		},
		{
			name: "id lookup (client DNS) - success",
			fields: fields{
				trustedCAs: aporetoCAPool,
			},
			args: args{
				verifiedChains: [][]*x509.Certificate{
					{
						aporetoClientDNSCertWithExtension,
						aporetoCertRoot,
					},
				},
				policyReporter: &policyReporter{
					ipret: true,
					idret: true,
				},
			},
			want: want{
				err:     false,
				ipCount: 0,
				idCount: 1,
			},
		},
		{
			name: "id lookup (server) - success",
			fields: fields{
				trustedCAs: aporetoCAPool,
			},
			args: args{
				verifiedChains: [][]*x509.Certificate{
					{
						aporetoServerCertWithExtension,
						aporetoCertRoot,
					},
				},
				policyReporter: &policyReporter{
					ipret: true,
					idret: true,
				},
			},
			want: want{
				err:     false,
				ipCount: 0,
				idCount: 1,
			},
		},
		{
			name: "id lookup (server) - must have client id - failure",
			fields: fields{
				trustedCAs: aporetoCAPool,
			},
			args: args{
				policyReporter: &policyReporter{
					ipret: true,
					idret: true,
				},
				mustHaveClientIDCert: true,
			},
			want: want{
				err:     true,
				ipCount: 0,
				idCount: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New(tt.fields.trustedCAs)
			err := v.VerifyPeerCertificate(tt.args.rawCerts, tt.args.verifiedChains, tt.args.policyReporter, tt.args.mustHaveClientIDCert)
			if (err != nil) != tt.want.err {
				t.Errorf("verifier.VerifyPeerCertificate() error = %v, want.err %v", err, tt.want.err)
				return
			}
			if tt.args.policyReporter.id != tt.want.idCount {
				t.Errorf("verifier.VerifyPeerCertificate() id have = %v, want %v", tt.args.policyReporter.id, tt.want.idCount)
				return
			}
			if tt.args.policyReporter.ip != tt.want.ipCount {
				t.Errorf("verifier.VerifyPeerCertificate() ip have = %v, want %v", tt.args.policyReporter.ip, tt.want.ipCount)
				return
			}
		})
	}
}
