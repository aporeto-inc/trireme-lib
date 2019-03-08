package iptablesctrl

var triremChains = `
{{if isLocalServer}}-t {{.MangleTable}} -N {{.HostInput}}
-t {{.MangleTable}} -N {{.HostOutput}}
-t {{.MangleTable}} -N {{.NetworkSvcInput}}
-t {{.MangleTable}} -N {{.NetworkSvcOutput}}
-t {{.MangleTable}} -N {{.TriremeInput}}
-t {{.MangleTable}} -N {{.TriremeOutput}}
-t {{.MangleTable}} -N {{.UIDInput}}
-t {{.MangleTable}} -N {{.UIDOutput}}
{{end}}-t {{.MangleTable}} -N {{.MangleProxyAppChain}}
-t {{.MangleTable}} -N {{.MangleProxyNetChain}}
-t {{.NatTable}} -N {{.NatProxyAppChain}}
-t {{.NatTable}} -N {{.NatProxyNetChain}}
`

var globalRules = `
{{.MangleTable}} INPUT -j {{ .MangleProxyNetChain }}
{{.MangleTable}} INPUT -p udp -m set --match-set {{.TargetNetSet}} dst -m string --string {{.UDPSignature}} --algo bm --to 65535 -j NFQUEUE --queue-bypass --queue-balance {{.QueueBalanceNetSynAck}}
{{.MangleTable}} INPUT -m connmark --mark {{.DefaultConnmark}} -j ACCEPT
{{.MangleTable}} INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceNetSynAck}} --queue-bypass
{{.MangleTable}} INPUT -p tcp -m set --match-set {{.TargetNetSet}} src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance {{.QueueBalanceNetSyn}} --queue-bypass
{{if isLocalServer}}
{{.MangleTable}} INPUT -j {{.UIDInput}}
{{.MangleTable}} INPUT -j {{.TriremeInput}}
{{.MangleTable}} INPUT -j {{.NetworkSvcInput}}
{{.MangleTable}} INPUT -j {{.HostInput}}
{{end}}


{{.MangleTable}} OUTPUT -m mark --mark {{.RawSocketMark}} -j ACCEPT
{{.MangleTable}} OUTPUT -j {{.MangleProxyAppChain}}
{{.MangleTable}} OUTPUT -m connmark --mark {{.DefaultConnmark}} -j ACCEPT
{{if isLocalServer}}
{{.MangleTable}} OUTPUT -j {{.UIDOutput}}{{end}}
{{.MangleTable}} OUTPUT -p tcp -m set --match-set {{.TargetNetSet}} dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark {{.InitialMarkVal}}
{{.MangleTable}} OUTPUT -p tcp -m set --match-set {{.TargetNetSet}} dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceAppSynAck}} --queue-bypass
{{if isLocalServer}}
{{.MangleTable}} OUTPUT -j {{.TriremeOutput}}
{{.MangleTable}} OUTPUT -j {{.NetworkSvcOutput}}
{{.MangleTable}} OUTPUT -j {{.HostOutput}}{{end}}

{{.MangleTable}} {{.MangleProxyAppChain}} -m mark --mark {{.ProxyMark}} -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -m mark --mark {{.ProxyMark}} -j ACCEPT

{{.NatTable}} {{.NatProxyAppChain}} -m mark --mark {{.ProxyMark}} -j ACCEPT
{{.NatTable}} {{.NatProxyNetChain}} -m mark --mark {{.ProxyMark}} -j ACCEPT
`

var cgroupRules = `
{{if isTCPPorts}}
{{.MangleTable}} {{.NetSection}} -p tcp -m multiport --destination-ports {{.TCPPorts}} -m comment --comment Container-specific-chain -j {{.NetChain}}
{{else}}
{{.MangleTable}} {{.NetSection}} -p tcp -m set --match-set {{.TCPPortSet}} dst -m comment --comment Container-specific-chain -j {{.NetChain}}
{{end}}

{{if isHostPU}}
{{.MangleTable}} {{.NetSection}} -p udp -m comment --comment traffic-same-pu -m mark --mark {{.Mark}} -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT
{{end}}

{{if isUDPPorts}}
{{.MangleTable}} {{.NetSection}} -p udp -m multiport --destination-ports {{.UDPPorts}} -m comment --comment Container-specific-chain -j {{.NetChain}}
{{end}}

{{.MangleTable}} {{.AppSection}} -m cgroup --cgroup {{.Mark}} -m comment --comment Server-specific-chain -j MARK --set-mark {{.Mark}}
{{if isHostPU}}
{{.MangleTable}} {{.AppSection}} -p udp -m mark --mark {{.Mark}} -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -m state --state NEW -j NFLOG --nflog-prefix {{.NFLOGPrefix}} --nflog-group 10
{{.MangleTable}} {{.AppSection}} -p udp -m comment --comment traffic-same-pu -m mark --mark {{.Mark}} -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT
{{end}}
{{.MangleTable}} {{.AppSection}} -m cgroup --cgroup {{.Mark}} -m comment --comment Server-specific-chain -j {{.AppChain}}
`

var containerPuRules = `
{{.MangleTable}} {{.AppSection}} -p udp -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -m state --state NEW -j NFLOG --nflog-prefix {{.NFLOGPrefix}} --nflog-group 10
{{.MangleTable}} {{.AppSection}} -p udp -m comment --comment traffic-same-pu -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT
{{.MangleTable}} {{.AppSection}} -m comment --comment Container-specific-chain -j {{.AppChain}}

{{.MangleTable}} {{.NetSection}} -p udp -m comment --comment traffic-same-pu -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT
{{.MangleTable}} {{.NetSection}} -m comment --comment Container-specific-chain -j {{.NetChain}}`

var uidPuRules = `
{{.MangleTable}} {{.PreRouting}} -m set --match-set {{.PortSet}} dst -j MARK --set-mark {{.Mark}}

{{.MangleTable}} UIDCHAIN -m owner --uid-owner {{.UID}} -j MARK --set-mark {{.Mark}}
{{.MangleTable}} UIDCHAIN -m mark --mark {{.Mark}} -m comment --comment Server-specific-chain -j {{.AppChain}}


{{.MangleTable}} UIDInput -p tcp -m mark --mark {{.Mark}} -m comment --comment Container-specific-chain -j {{.NetChain}}`

var excludedACLs = `
{{$root := .}}
{{range .Exclusions}}
{{$root.MangleTable}} {{$root.AppChain}} -d {{.}} -j ACCEPT
{{$root.MangleTable}} {{$root.NetChain}} -s {{.}} -j ACCEPT
{{end}}
`
var excludedNatACLs = `
{{$root := .}}
{{range .Exclusions}}
	{{$root.NatTable}} {{$root.NetChain}} -p tcp -m set --match-set {{$root.SrvIPSet}} dst -m mark ! --mark {{$root.ProxyMark}} -s {{.}} -j ACCEPT
		{{if isCgroupSet}}
			{{$root.NatTable}} {{$root.AppChain}} -m set --match-set {{$root.DestIPSet}} dst,dst -m mark ! --mark {{$root.ProxyMark}} -m cgroup --cgroup {{$root.CgroupMark}} -d {{.}} -j ACCEPT
		{{else}}
			{{$root.NatTable}} {{$root.AppChain}} -m set --match-set {{$root.DestIPSet}} dst,dst -m mark ! --mark {{$root.ProxyMark}} -d {{.}} -j ACCEPT
		{{end}}
{{end}}
`

var acls = `
{{range .RejectObserveApply}}
{{joinRule .}}
{{end}}

{{range .RejectNotObserved}}
{{joinRule .}}
{{end}}

{{range .RejectObserveContinue}}
{{joinRule .}}
{{end}}

{{range .AcceptObserveContinue}}
{{joinRule .}}
{{end}}

{{range .AcceptNotObserved}}
{{joinRule .}}
{{end}}

{{range .AcceptObserveApply}}
{{joinRule .}}
{{end}}
`

var trapRules = `
{{if needDnsRules}}
{{.MangleTable}} {{.AppChain}} -p udp -m udp --dport 53 -j ACCEPT
{{end}}
{{.MangleTable}} {{.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance {{.QueueBalanceAppSyn}}
{{.MangleTable}} {{.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance {{.QueueBalanceAppAck}}
{{.MangleTable}} {{.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceAppAck}}
{{.MangleTable}} {{.AppChain}} -p udp -m set --match-set TargetNetSet dst -j NFQUEUE --queue-balance {{.QueueBalanceAppAck}}
{{.MangleTable}} {{.AppChain}} -p tcp -m state --state ESTABLISHED -j ACCEPT
{{.MangleTable}} {{.AppChain}} -d 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 10 --nflog-prefix {{.NFLOGPrefix}}
{{.MangleTable}} {{.AppChain}} -d 0.0.0.0/0 -j DROP

{{if needDnsRules}}
{{.MangleTable}} {{.NetChain}} -p udp -m udp --sport 53 -j ACCEPT
{{end}}
{{.MangleTable}} {{.NetChain}} -p tcp -m set --match-set TargetNetSet src -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance {{.QueueBalanceNetSyn}}
{{.MangleTable}} {{.NetChain}} -p tcp -m set --match-set TargetNetSet src -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance {{.QueueBalanceNetSyn}}
{{.MangleTable}} {{.NetChain}} -p udp -m set --match-set TargetNetSet src -m statistic --mode nth --every {{.Numpackets}} --packet {{.InitialCount}} -j NFQUEUE --queue-balance {{.QueueBalanceNetAck}}
{{.MangleTable}} {{.NetChain}} -p tcp -m state --state ESTABLISHED -j ACCEPT
{{.MangleTable}} {{.NetChain}} -s 0.0.0.0/0 -m state --state NEW -j NFLOG --nflog-group 11 --nflog-prefix {{.NFLOGPrefix}}
{{.MangleTable}} {{.NetChain}} -s 0.0.0.0/0 -j DROP
`

var proxyChainRules = `
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m tcp --sport {{.ProxyPort}} -j ACCEPT
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -j ACCEPT
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j ACCEPT

{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.DestIPSet}} src,src -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -m addrtype --src-type LOCAL -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m tcp --dport {{.ProxyPort}} -j ACCEPT


{{if isCgroupSet}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -m cgroup --cgroup {{.CgroupMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{else}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{end}}

{{.NatTable}} {{.NatProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}`

var deleteChains = `
-t {{.MangleTable}} -F INPUT
-t {{.MangleTable}} -F OUTPUT
-t {{.MangleTable}} -F PREROUTING

{{if isLocalServer}}
-t {{.MangleTable}} -F {{.HostInput}}
-t {{.MangleTable}} -X {{.HostInput}}

-t {{.MangleTable}} -F {{.HostOutput}}
-t {{.MangleTable}} -X {{.HostOutput}}

-t {{.MangleTable}} -F {{.TriremeInput}}
-t {{.MangleTable}} -X {{.TriremeInput}}

-t {{.MangleTable}} -F {{.TriremeOutput}}
-t {{.MangleTable}} -X {{.TriremeOutput}}

-t {{.MangleTable}} -F {{.NetworkSvcInput}}
-t {{.MangleTable}} -X {{.NetworkSvcInput}}

-t {{.MangleTable}} -F {{.NetworkSvcOutput}}
-t {{.MangleTable}} -X {{.NetworkSvcOutput}}

-t {{.MangleTable}} -F {{.UIDInput}}
-t {{.MangleTable}} -X {{.UIDInput}}

-t {{.MangleTable}} -F {{.UIDOutput}}
-t {{.MangleTable}} -X {{.UIDOutput}}
{{end}}


-t {{.MangleTable}} -F {{.MangleProxyAppChain}}
-t {{.MangleTable}} -X {{.MangleProxyAppChain}}

-t {{.MangleTable}} -F {{.MangleProxyNetChain}}
-t {{.MangleTable}} -X {{.MangleProxyNetChain}}

-t {{.NatTable}} -F {{.NatProxyAppChain}}
-t {{.NatTable}} -X {{.NatProxyAppChain}}

-t {{.NatTable}} -F {{.NatProxyNetChain}}
-t {{.NatTable}} -X {{.NatProxyNetChain}}
`

var deleteNatRules = `
{{.NatTable}} PREROUTING -p tcp -m addrtype --dst-type LOCAL -j {{.NatProxyNetChain}}
{{.NatTable}} OUTPUT -j {{.NatProxyAppChain}}
`

// Legacy ACLs for kernels with no cgroup match.
var legacyExcludedNatACLs = `
{{$root := .}}
{{range .Exclusions}}
	{{$root.NatTable}} {{$root.NetChain}} -p tcp -m set --match-set {{$root.SrvIPSet}} dst -m mark ! --mark {{$root.ProxyMark}} -s {{.}} -j ACCEPT
		{{if isCgroupSet}}
			{{$root.NatTable}} {{$root.AppChain}} -p tcp -m set --match-set {{$root.DestIPSet}} dst,dst -m mark ! --mark {{$root.ProxyMark}} -m multiport --source-ports {{$root.TCPPorts}} -d {{.}} -j ACCEPT
		{{else}}
			{{$root.NatTable}} {{$root.AppChain}} -m set --match-set {{$root.DestIPSet}} dst,dst -m mark ! --mark {{$root.ProxyMark}} -d {{.}} -j ACCEPT
		{{end}}
{{end}}
`

var legacyProxyRules = `
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m tcp --sport {{.ProxyPort}} -j ACCEPT
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -j ACCEPT
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j ACCEPT

{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.DestIPSet}} src,src -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -m addrtype --src-type LOCAL -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m tcp --dport {{.ProxyPort}} -j ACCEPT


{{if isCgroupSet}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -m multiport --source-ports {{.TCPPorts}} -j REDIRECT --to-ports {{.ProxyPort}}
{{else}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{end}}

{{.NatTable}} {{.NatProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}`
