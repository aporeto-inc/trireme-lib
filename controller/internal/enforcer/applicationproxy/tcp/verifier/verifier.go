package verifier

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"sync"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// aporetoASNTagsExtension holds the value of the Aporeto Tags Extension
var aporetoASNTagsExtension asn1.ObjectIdentifier

// aporetoPingExtension holds the value of the Aporeto Ping Extension
var aporetoPingExtension asn1.ObjectIdentifier

// PolicyReporter is the interface to allow looking up policies and report stats
type PolicyReporter interface {
	IDLookup(remoteContoller, remotePUID string, tags *policy.TagStore) bool
	IPLookup() bool
	Policy(tags *policy.TagStore) (*policy.FlowPolicy, *policy.FlowPolicy)
	ReportStats(remoteType collector.EndPointType, remoteController string, remotePUID string, mode string, report *policy.FlowPolicy, packet *policy.FlowPolicy, accept bool)
}

// Verifier interface defines the methods a verifier must implement
type Verifier interface {

	// TrustCA replaces the trusted CA list.
	TrustCAs(caPool *x509.CertPool)

	// VerifyPeerCertificate verifies if this TLS connection should be admitted.
	VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, policy PolicyReporter, mustHaveClientIDCert bool) error
}

// verifier implements the Verifier interface
type verifier struct {
	sync.RWMutex
	// trustedCAs stores the list of certs to be trusted
	trustedCAPool *x509.CertPool
}

func init() {
	aporetoASNTagsExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50798, 1, 1}
	aporetoPingExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 50798, 1, 4}
}

// New returns a new instance of Verifier
func New(caPool *x509.CertPool) Verifier {
	return &verifier{
		trustedCAPool: caPool,
	}
}

// certHasDNSOrIPSAN checks if a given name exists in a SAN for the certificate.
func certHasDNSOrIPSAN(san string, cert *x509.Certificate) bool {

	// san found in SAN in certs
	for _, name := range cert.DNSNames {
		if san == name {
			return true
		}
	}

	for _, ip := range cert.IPAddresses {
		if san == ip.String() {
			return true
		}
	}

	return false
}

// TrustCA replaces the trusted CA list.
func (v *verifier) TrustCAs(caPool *x509.CertPool) {

	// Update verifier
	v.Lock()
	v.trustedCAPool = caPool
	v.Unlock()
}

// VerifyPeerCertificate validates that policies allow mTLS between two enforcers based on
// aporeto-tags. If no aporeto tags are found, it applies IP based ACLs.
//
func (v *verifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, pr PolicyReporter, mustHaveClientIDCert bool) error {

	v.RLock()
	opts := x509.VerifyOptions{
		Roots: v.trustedCAPool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}
	v.RUnlock()

	// Is this an Aporeto Cert we are trusting
	if opts.Roots != nil {
		for _, certChain := range verifiedChains {
			tags := []string{}
			ping := false
			for _, cert := range certChain {
				for _, e := range cert.Extensions {
					if e.Id.Equal(aporetoPingExtension) {
						ping = true
						continue
					}

					// If there is an Aporeto extension, get the value
					if e.Id.Equal(aporetoASNTagsExtension) {
						if err := json.Unmarshal(e.Value, &tags); err == nil {
							if ping {
								break
							}
						}
					}
				}

				// No Aporeto tags
				if len(tags) == 0 {
					continue
				}

				rtags := policy.NewTagStoreFromSlice(tags)

				// check if we have remote controller
				rcontroller, ok := rtags.Get(policy.TagKeyController)
				if !ok {
					continue
				}

				// check if $identity == processingunit
				if pu, ok := rtags.Get(policy.TagKeyIdentity); !ok && pu != policy.TagValueProcessingUnit {
					continue
				}

				// check if we have remote puid
				rpuid, ok := rtags.Get(policy.TagKeyID)
				if !ok {
					continue
				}

				if _, err := cert.Verify(opts); err != nil {
					continue
				}

				// TODO: Check controller against verified CA
				// fmt.Println(strings.Join(tags, " "))
				// if !certHasDNSOrIPSAN(controller, cert) {
				// 	fmt.Println("No IP or DNS SAN", strings.Join(cert.DNSNames, " "))
				// 	continue
				// }

				// If ping is enabled in the certificate, we defer the policy lookup and the server
				// application will never receive any packets related to ping irrespective of policy.
				if ping {
					return nil
				}

				if !pr.IDLookup(rcontroller, rpuid, rtags) {
					return fmt.Errorf("ID policy lookup rejection")
				}

				return nil
			}
		}
	}

	if mustHaveClientIDCert {
		return fmt.Errorf("ID lookup not performed")
	}

	if !pr.IPLookup() {
		return fmt.Errorf("IP policy lookup rejection")
	}

	return nil
}
