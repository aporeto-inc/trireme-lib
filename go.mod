module go.aporeto.io/trireme-lib/v11

go 1.13

// Aporeto modules
require (
	github.com/aporeto-inc/go-ipset v1.5.3-0.20191002024208-fab1debc861a
	github.com/aporeto-inc/gopkt v0.0.0-20200314001002-dfa2409b099c
	github.com/aporeto-inc/oxy v1.2.3-0.20200204041758-974988a35e97
	go.aporeto.io/netlink-go v1.42.1-0.20200313235738-e32d68592a75
	go.aporeto.io/tg v1.34.1-0.20191212031200-49e4a3e985d8
)

// 3rd party
require (
	github.com/DavidGamba/go-getoptions v0.17.0
	github.com/blang/semver v3.5.1+incompatible
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/cespare/xxhash v1.1.0
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/dchest/siphash v1.2.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/envoyproxy/go-control-plane v0.9.2
	github.com/envoyproxy/protoc-gen-validate v0.1.0
	github.com/gogo/googleapis v1.3.2
	github.com/gogo/protobuf v1.3.1
	github.com/golang/mock v1.4.2
	github.com/golang/protobuf v1.3.3
	github.com/google/gopacket v1.1.17
	github.com/iovisor/gobpf v0.0.0-20191219090757-e72091e3c5e6
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/magiconair/properties v1.8.1
	github.com/mattn/go-shellwords v1.0.9
	github.com/mdlayher/netlink v1.0.1-0.20191210152442-a1644773bc99
	github.com/miekg/dns v1.1.27
	github.com/minio/minio v0.0.0-20200203082420-9bbf5cb74f55
	github.com/mitchellh/hashstructure v1.0.0
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/pkg/errors v0.9.1
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
	golang.org/x/net v0.0.0-20200226121028-0de0cce0169b
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/sys v0.0.0-20200202164722-d101bd2416d5
	google.golang.org/genproto v0.0.0-20200128133413-58ce757ed39b
	google.golang.org/grpc v1.27.0
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
)

// Kubernetes
require (
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/containerd/containerd v1.3.3 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	golang.org/x/tools v0.0.0-20200313205530-4303120df7d8 // indirect
	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	sigs.k8s.io/controller-runtime v0.4.0
)

// NOTE: we must use the replace directive as below, otherwise we might get
// wrong versions of Kubernetes inherited through other modules.
// The version below here matches exactly what the controller-runtime uses.
// Ensure to keep them in sync.
replace (
	k8s.io/api => k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20190918161926-8f644eb6e783
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190918160344-1fbdaa4c8d90
	k8s.io/utils => k8s.io/utils v0.0.0-20190801114015-581e00157fb1
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.4.0
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
