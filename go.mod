module go.aporeto.io/trireme-lib/v11

go 1.13

require (
	// others
	github.com/DavidGamba/go-getoptions v0.17.0
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/aporeto-inc/go-ipset v0.0.0-20191002024208-fab1debc861a
	github.com/aporeto-inc/gopkt v0.0.0-20200127181821-1af745e7e4c1
	github.com/aporeto-inc/oxy v1.1.0
	github.com/blang/semver v3.5.0+incompatible
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/cespare/xxhash v1.1.0
	github.com/containerd/containerd v1.3.2 // indirect
	github.com/coreos/go-iptables v0.4.3
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/dchest/siphash v1.2.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0
	github.com/envoyproxy/go-control-plane v0.9.2
	github.com/envoyproxy/protoc-gen-validate v0.1.0
	github.com/ghedo/go.pkt v0.0.0-20190615170926-3c8ef803c2f7 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gogo/googleapis v1.3.0
	github.com/gogo/protobuf v1.3.1
	github.com/golang/mock v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/google/gopacket v1.1.17
	github.com/hashicorp/go-version v1.2.0
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/magiconair/properties v1.8.1
	github.com/mattn/go-shellwords v1.0.6
	github.com/mdlayher/netlink v0.0.0-20191008140946-2a17fd90af51
	github.com/miekg/dns v1.1.22
	github.com/minio/minio v0.0.0-20191008225043-d2a8be6fc228
	github.com/mitchellh/hashstructure v1.0.0
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/pkg/errors v0.8.1
	github.com/rs/xid v1.2.1
	github.com/shirou/gopsutil v2.19.9+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	github.com/smartystreets/assertions v1.0.0
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a
	github.com/spaolacci/murmur3 v0.0.0-20180118202830-f09979ecbc72
	github.com/stretchr/testify v1.4.0
	github.com/ti-mo/conntrack v0.0.0-20190323132511-733fb77b6071
	github.com/ugorji/go/codec v1.1.7
	github.com/vmihailenco/msgpack v4.0.4+incompatible
	github.com/vulcand/oxy v1.0.0 // indirect
	// aporeto repos
	go.aporeto.io/netlink-go v1.40.0
	go.aporeto.io/tg v1.34.1-0.20191212031200-49e4a3e985d8
	go.uber.org/zap v1.10.0
	golang.org/x/net v0.0.0-20191009170851-d66e71096ffb
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sys v0.0.0-20191105231009-c1f44814a5cd
	google.golang.org/genproto v0.0.0-20191009194640-548a555dbc03
	google.golang.org/grpc v1.25.1
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
)

// Kubernetes ( consistent with https://github.com/aporeto-inc/aporeto-operator/blob/master/go.mod )
require (
	go.aporeto.io/trireme-lib v10.259.0+incompatible
	k8s.io/api v0.0.0-20191102065807-b98ecd433b91
	k8s.io/apimachinery v0.0.0-20191102025618-50aa20a7b23f
	k8s.io/client-go v0.0.0-20191016110837-54936ba21026
	sigs.k8s.io/controller-runtime v0.3.0
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
