module go.aporeto.io/trireme-lib/v11

go 1.13

replace go.aporeto.io/trireme-lib => go.aporeto.io/trireme-lib/v11 v11.0.0-rc3

// Aporeto modules
require (
	go.aporeto.io/netlink-go v1.41.1
	go.aporeto.io/tg v1.34.1-0.20191212031200-49e4a3e985d8
)

require (
	// others
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/DavidGamba/go-getoptions v0.17.0
	github.com/aporeto-inc/go-ipset v1.7.1
	github.com/aporeto-inc/gopkt v0.0.0-20200127181821-1af745e7e4c1
	github.com/aporeto-inc/oxy v1.2.2
	github.com/blang/semver v3.5.1+incompatible
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/cespare/xxhash v1.1.0
	github.com/containerd/containerd v1.3.2 // indirect
	github.com/coreos/etcd v3.3.15+incompatible // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/dchest/siphash v1.2.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/envoyproxy/go-control-plane v0.9.2
	github.com/envoyproxy/protoc-gen-validate v0.1.0
	github.com/go-logr/zapr v0.1.0 // indirect
	github.com/go-openapi/validate v0.19.2 // indirect
	github.com/gogo/googleapis v1.3.2
	github.com/gogo/protobuf v1.3.1
	github.com/golang/mock v1.4.0
	github.com/golang/protobuf v1.3.3
	github.com/google/gopacket v1.1.17
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/iovisor/gobpf v0.0.0-20191219090757-e72091e3c5e6
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/magiconair/properties v1.8.1
	github.com/mailgun/timetools v0.0.0-20170619190023-f3a7b8ffff47 // indirect
	github.com/mattn/go-shellwords v1.0.9
	github.com/mdlayher/netlink v1.0.1-0.20191210152442-a1644773bc99
	github.com/miekg/dns v1.1.27
	github.com/minio/minio v0.0.0-20200203082420-9bbf5cb74f55
	github.com/mitchellh/hashstructure v1.0.0
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/onsi/ginkgo v1.11.0 // indirect
	github.com/onsi/gomega v1.8.1 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.0.0-20171018203845-0dec1b30a021 // indirect
	github.com/rs/xid v1.2.1
	github.com/shirou/gopsutil v2.20.1+incompatible
	github.com/smartystreets/assertions v1.0.0
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a
	github.com/spaolacci/murmur3 v1.1.0
	github.com/stretchr/testify v1.4.0
	github.com/ti-mo/conntrack v0.0.0-20191219100429-c9b176489c1a
	github.com/ugorji/go/codec v1.1.7
	github.com/vmihailenco/msgpack v4.0.4+incompatible
	go.uber.org/zap v1.13.0
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20200202164722-d101bd2416d5
	gomodules.xyz/jsonpatch/v2 v2.0.1 // indirect
	google.golang.org/genproto v0.0.0-20200128133413-58ce757ed39b
	google.golang.org/grpc v1.27.0
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
	gotest.tools v2.2.0+incompatible // indirect
)

// Kubernetes ( consistent with https://github.com/aporeto-inc/aporeto-operator/blob/master/go.mod )
require (
	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/client-go v0.0.0-20181213151034-8d9ed539ba31
	k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269 // indirect
	k8s.io/utils v0.0.0-20190801114015-581e00157fb1 // indirect
	sigs.k8s.io/structured-merge-diff v0.0.0-20190817042607-6149e4549fca // indirect
)

// Kubernetes:
// NOTE: we must use the replace directive as below, otherwise we might get
// wrong versions of Kubernetes inherited through other modules.
// The version below here is Kubernetes 1.15.5
replace (
	k8s.io/api => k8s.io/api v0.0.0-20191016110246-af539daaa43a
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191016113439-b64f2075a530
	k8s.io/apimachinery => k8s.io/apimachinery v0.15.10-beta.0
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191016110837-54936ba21026
	k8s.io/utils => k8s.io/utils v0.0.0-20190801114015-581e00157fb1
	sigs.k8s.io/controller-runtime => github.com/aporeto-inc/controller-runtime v0.4.1
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
