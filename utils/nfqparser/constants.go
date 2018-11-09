package nfqparser

const (
	nfqFilePath = "/proc/net/netfilter/nfnetlink_queue"
)

// NOTE: This is for unit test
var testNFQData = `      0  13206     0 2 65531     0     0        0  1
    1 3333107750     0 2 65531     0     0        0  1
    2 3881398569     0 2 65531     0     0        1  1
    3 2633750685     0 2 65531     0     0        0  1
    4 3605545056     0 2 65531     0     0        0  1
    5 3473230188     0 2 65531     0     0        2  1
    6 4025478776     0 2 65531     0     0        3  1
    7 2806986372     0 2 65531     0     0        1  1`
