package iptablesctrl

// Chains struct keeps track of trireme chains
type Chains struct {
	Table                     string
	HostInput                 string
	HostOutput                string
	NetworkSvcInput           string
	NetworkSvcOutput          string
	TriremeInput              string
	TriremeOutput             string
	EncryptNetworkService     string
	EncryptApplicationService string
	ProxyInput                string
	ProxyOutput               string
	UIDInput                  string
	UIDOutput                 string
}

type GlobalChains struct {
	Table                 string
	HostInput             string
	HostOutput            string
	NetworkSvcInput       string
	NetworkSvcOutput      string
	TriremeInput          string
	TriremeOutput         string
	ProxyInput            string
	ProxyOutput           string
	UIDInput              string
	UIDOutput             string
	UDPSignature          string
	DefaultConnmark       string
	QueueBalanceAppSyn    string
	QueueBalanceAppSynAck string
	QueueBalanceNetSyn    string
	QueueBalanceNetSynAck string
	targetNetworkSet      string
	InitialMarkVal        string
	RawSocketMark         string
	TargetNetSet          string
}

type PUChains struct {
	Table              string
	QueueBalanceAppSyn string
	QueueBalanceAppAck string
	QueueBalanceNetSyn string
	QueueBalanceNetAck string
	AppChain           string
	NetChain           string
	TargetNetSet       string
	Numpackets         string
	InitialCount       string
}

type CgroupChains struct {
	Table        string
	AppSection   string
	NetSection   string
	AppChain     string
	NetChain     string
	TargetNetSet string
	Mark         string
	NFLOGPrefix  string
	TCPPorts     string
	UDPPorts     string
	TCPPortSet   string
}

type ProxyRules struct {
	MangleTable         string
	NatTable            string
	DestIPSet           string
	SrvIPSet            string
	NatProxyNetChain    string
	NatProxyAppChain    string
	MangleProxyNetChain string
	MangleProxyAppChain string
	ProxyPort           string
	CgroupMark          string
	ProxyMark           string
}

type UIDRules struct {
	Table      string
	AppChain   string
	NetChain   string
	PreRouting string
	Mark       string
	UID        string
	PortSet    string
}

type ContainerRules struct {
	Table       string
	AppSection  string
	NetSection  string
	AppChain    string
	NetChain    string
	NFLOGPrefix string
}
