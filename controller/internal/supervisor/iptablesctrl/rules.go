package iptablesctrl

var triremChains = `
{{if isLocalServer}}-t {{.Table}} -N {{.HostInput}}
-t {{.Table}} -N {{.HostOutput}}
-t {{.Table}} -N {{.NetworkSvcInput}}
-t {{.Table}} -N {{.NetworkSvcOutput}}
-t {{.Table}} -N {{.TriremeInput}}
-t {{.Table}} -N {{.TriremeOutput}}
-t {{.Table}} -N {{.UIDInput}}
-t {{.Table}} -N {{.UIDOutput}}
{{end}}-t {{.Table}} -N {{.ProxyInput}}
-t {{.Table}} -N {{.ProxyOutput}}
`

var globalRules = `
{{.Table}} INPUT -j {{ .ProxyInput }}
{{.Table}} INPUT -p udp -m set --match-set {{.TargetNetSet}} dst -m string --string {{.UDPSignature}} --algo bm --to 65535 -j NFQUEUE --queue-bypass --queue-balance {{.QueueBalanceNetSynAck}}
{{.Table}} INPUT -m connmark --mark {{.DefaultConnmark}} -j ACCEPT
{{.Table}} INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceNetSynAck}} --queue-bypass
{{.Table}} INPUT -p tcp -m set --match-set {{.TargetNetSet}} src -m tcp --tcp-option 34 --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance {{.QueueBalanceNetSyn}} --queue-bypass
{{if isLocalServer}}
{{.Table}} INPUT -j {{.UIDInput}}
{{.Table}} INPUT -j {{.TriremeInput}}
{{.Table}} INPUT -j {{.NetworkSvcInput}}
{{.Table}} INPUT -j {{.HostInput}}
{{end}}


{{.Table}} OUTPUT -m mark --mark {{.RawSocketMark}} -j ACCEPT
{{.Table}} OUTPUT -j {{.ProxyOutput}}
{{.Table}} OUTPUT -m connmark --mark {{.DefaultConnmark}} -j ACCEPT
{{if isLocalServer}}
{{.Table}} OUTPUT -j {{.UIDOutput}}{{end}}
{{.Table}} OUTPUT -p tcp -m set --match-set {{.TargetNetSet}} dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j MARK --set-mark {{.InitialMarkVal}}
{{.Table}} OUTPUT -p tcp -m set --match-set {{.TargetNetSet}} dst -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceAppSynAck}} --queue-bypass
{{.Table}} OUTPUT -m connmark --mark {{.DefaultConnmark}} -j ACCEPT
{{if isLocalServer}}
{{.Table}} OUTPUT -j {{.TriremeOutput}}
{{.Table}} OUTPUT -j {{.NetworkSvcOutput}}
{{.Table}} OUTPUT -j {{.HostOutput}}{{end}}
`

var cgroupRules = `
{{if ifTCPPorts}}
{{.Table}} {{.NetSection}} -p tcp -m multiport --destination-ports {{.TCPPorts}} -m comment --comment Container-specific-chain -j {{.NetChain}}
{{else}}
{{.Table}} {{.NetSection}} -p tcp -m set --match-set {{.TCPPortSet}} dst -m comment --comment Container-specific-chain -j {{.NetChain}}
{{end}}

{{if isHostPU}}
{{.Table}} {{.NetSection}} -p udp -m comment --comment traffic-same-pu -m mark --mark {{.Mark}} -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT
{{end}}

{{if ifUDPPorts}}
{{.Table}} {{.NetSection}} -p udp -m multiport --destination-ports {{.UDPPorts}} -m comment --comment Container-specific-chain -j {{.NetChain}}
{{end}}

{{if isHostPU}}
{{.Table}} {{.AppSection}} -p udp -m mark --mark {{.Mark}} -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -m state --state NEW -j NFLOG --nflog-prefix {{.NFLOGPrefix}} --nflog-group 10
{{.Table}} {{.AppSection}} -p udp -m comment --comment traffic-same-pu -m mark --mark {{.Mark}} -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT
{{end}}
{{.Table}} {{.AppSection}} -m cgroup --cgroup {{.Mark}} -m comment --comment Server-specific-chain -j MARK --set-mark {{.Mark}}
{{.Table}} {{.AppSection}} -m cgroup --cgroup {{.Mark}} -m comment --comment Server-specific-chain -j {{.AppChain}}
`

var containerPuRules = `
{{.Table}} {{.AppSection}} -p udp -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -m state --state NEW -j NFLOG --nflog-prefix {{.NFLOGPrefix}} --nflog-group 10
{{.Table}} {{.AppSection}} -p udp -m comment --comment traffic-same-pu -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT
{{.Table}} {{.AppSection}} -m comment --comment Container-specific-chain -j {{.AppChain}}

{{.Table}} {{.NetSection}} -p udp -m comment --comment traffic-same-pu -m addrtype --src-type LOCAL -m addrtype --dst-type LOCAL -j ACCEPT
{{.Table}} {{.NetSection}} -m comment --comment Container-specific-chain -j {{.NetChain}}`

var uidPuRules = `
{{.Table}} {{.PreRouting}} -m set --match-set {{.PortSet}} dst -j MARK --set-mark {{.Mark}}

{{.Table}} UIDCHAIN -m owner --uid-owner {{.UID}} -j MARK --set-mark {{.Mark}}
{{.Table}} UIDCHAIN -m mark --mark {{.Mark}} -m comment --comment Server-specific-chain -j {{.AppChain}}


{{.Table}} UIDInput -p tcp -m mark --mark {{.Mark}} -m comment --comment Container-specific-chain -j {{.NetChain}}`

var trapRules = `
{{if needDnsRules}}
{{.Table}} {{.AppChain}} -p udp -m udp --dport 53 -j ACCEPT
{{end}}
{{.Table}} {{.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance {{.QueueBalanceAppSyn}}
{{.Table}} {{.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance {{.QueueBalanceAppAck}}
{{.Table}} {{.AppChain}} -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-balance {{.QueueBalanceAppAck}}
{{.Table}} {{.AppChain}} -p udp -m set --match-set TargetNetSet dst -j NFQUEUE --queue-balance {{.QueueBalanceAppAck}}
{{.Table}} {{.AppChain}} -p tcp -m state --state ESTABLISHED -j ACCEPT


{{if needDnsRules}}
{{.Table}} {{.NetChain}} -p udp -m udp --sport 53 -j ACCEPT
{{end}}
{{.Table}} {{.NetChain}} -p tcp -m set --match-set TargetNetSet src -m tcp --tcp-flags SYN,ACK SYN -j NFQUEUE --queue-balance {{.QueueBalanceNetSyn}}
{{.Table}} {{.NetChain}} -p tcp -m set --match-set TargetNetSet src -m tcp --tcp-flags SYN,ACK ACK -j NFQUEUE --queue-balance {{.QueueBalanceNetSyn}}
{{.Table}} {{.NetChain}} -p udp -m set --match-set TargetNetSet src -m statistic --mode nth --every {{.Numpackets}} --packet {{.InitialCount}} -j NFQUEUE --queue-balance {{.QueueBalanceNetAck}}
{{.Table}} {{.NetChain}} -p tcp -m state --state ESTABLISHED -j ACCEPT
`

var proxyChainRules = `
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m tcp --sport {{.ProxyPort}} -j ACCEPT
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -j ACCEPT
{{.MangleTable}} {{.MangleProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j ACCEPT

{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.DestIPSet}} src,src -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} src -m addrtype --src-type LOCAL -j ACCEPT
{{.MangleTable}} {{.MangleProxyNetChain}} -p tcp -m tcp --dport {{.ProxyPort}} -j ACCEPT


{{if ifCgroupSet}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -m cgroup --cgroup {{.CgroupMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{else}}
{{.NatTable}} {{.NatProxyAppChain}} -p tcp -m set --match-set {{.DestIPSet}} dst,dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}
{{end}}

{{.NatTable}} {{.NatProxyNetChain}} -p tcp -m set --match-set {{.SrvIPSet}} dst -m mark ! --mark {{.ProxyMark}} -j REDIRECT --to-ports {{.ProxyPort}}`
