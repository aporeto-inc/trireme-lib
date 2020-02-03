module go.aporeto.io/trireme-lib/v11

go 1.13

replace go.aporeto.io/trireme-lib => go.aporeto.io/trireme-lib/v11 v11.0.0-rc3

// Aporeto modules
require (
	go.aporeto.io/netlink-go v1.41.1
	go.aporeto.io/tg v1.34.1-0.20191212031200-49e4a3e985d8
	go.aporeto.io/trireme-lib v10.259.0+incompatible // indirect
)

require (
	// others
	github.com/DavidGamba/go-getoptions v0.17.0
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/Sirupsen/logrus v1.4.2 // indirect
	github.com/aporeto-inc/go-ipset v1.7.1
	github.com/aporeto-inc/gopkt v0.0.0-20200127181821-1af745e7e4c1
	github.com/aporeto-inc/oxy v1.2.2
	github.com/blang/semver v3.5.1+incompatible
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/cespare/xxhash v1.1.0
	github.com/cncf/udpa/go v0.0.0-20200124205748-db4b343e48c1 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/dchest/siphash v1.2.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.4.0 // indirect
	github.com/envoyproxy/go-control-plane v0.9.2
	github.com/envoyproxy/protoc-gen-validate v0.1.0
	github.com/ghedo/go.pkt v0.0.0-20200130003937-c2d1c878e492 // indirect
	github.com/gogo/googleapis v1.3.2
	github.com/gogo/protobuf v1.3.1
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/mock v1.4.0
	github.com/golang/protobuf v1.3.3
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/gopacket v1.1.17
	github.com/google/uuid v1.1.1 // indirect
	github.com/googleapis/gnostic v0.4.1 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/iovisor/gobpf v0.0.0-20191219090757-e72091e3c5e6
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/magiconair/properties v1.8.1
	github.com/mattn/go-shellwords v1.0.9
	github.com/mdlayher/netlink v1.0.1-0.20191210152442-a1644773bc99
	github.com/miekg/dns v1.1.27
	github.com/minio/minio v0.0.0-20200203082420-9bbf5cb74f55
	github.com/mitchellh/hashstructure v1.0.0
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.4.0 // indirect
	github.com/rs/xid v1.2.1
	github.com/shirou/gopsutil v2.20.1+incompatible
	github.com/smartystreets/assertions v1.0.0
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a
	github.com/spaolacci/murmur3 v1.1.0
	github.com/stretchr/testify v1.4.0
	github.com/ti-mo/conntrack v0.0.0-20191219100429-c9b176489c1a
	github.com/ugorji/go/codec v1.1.7
	github.com/vmihailenco/msgpack v4.0.4+incompatible
	go.uber.org/atomic v1.5.1 // indirect
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.13.0
	golang.org/x/crypto v0.0.0-20200128174031-69ecbb4d6d5d // indirect
	golang.org/x/lint v0.0.0-20200130185559-910be7a94367 // indirect
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20200202164722-d101bd2416d5
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.org/x/tools v0.0.0-20200203023011-6f24f261dadb // indirect
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/genproto v0.0.0-20200128133413-58ce757ed39b
	google.golang.org/grpc v1.27.0
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
	gopkg.in/yaml.v2 v2.2.8 // indirect
)

// Kubernetes ( consistent with https://github.com/aporeto-inc/aporeto-operator/blob/master/go.mod )
require (
	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/client-go v0.0.0-20191016110837-54936ba21026
	k8s.io/klog v1.0.0 // indirect
	k8s.io/kube-openapi v0.0.0-20200130172213-cdac1c71ff9f // indirect
	k8s.io/utils v0.0.0-20200124190032-861946025e34 // indirect
	sigs.k8s.io/controller-runtime v0.4.0
)

// Kubernetes:
// NOTE: we must use the replace directive as below, otherwise we might get
// wrong versions of Kubernetes inherited through other modules.
// The version below here is Kubernetes 1.15.5
replace (
	k8s.io/api => k8s.io/api v0.0.0-20191016110246-af539daaa43a
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191016113439-b64f2075a530
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20191004115701-31ade1b30762
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20191016111841-d20af8c7efc5
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191016110837-54936ba21026
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.3.0
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0
)

// others
replace (
	github.com/docker/docker => github.com/docker/engine v1.4.2-0.20191113042239-ea84732a7725
	github.com/gorilla/rpc v1.2.0+incompatible => github.com/gorilla/rpc v1.2.0
)

// Sirupsen --- this configuration I've found to work consistently
replace (
	github.com/Sirupsen/logrus v1.0.5 => github.com/sirupsen/logrus v1.0.5
	github.com/Sirupsen/logrus v1.3.0 => github.com/sirupsen/logrus v1.3.0
	github.com/Sirupsen/logrus v1.4.0 => github.com/sirupsen/logrus v1.4.2
	github.com/Sirupsen/logrus v1.4.2 => github.com/sirupsen/logrus v1.4.1
)
