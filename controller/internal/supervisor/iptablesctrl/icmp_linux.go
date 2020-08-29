// +build !windows

package iptablesctrl

/*
#cgo linux LDFLAGS: -L/tmp -lpcap
#include<string.h>
#include<stdlib.h>
#include<pcap.h>

char bpf_program[1500];

char *compileBPF(const char *expr) {
	struct bpf_program program;
	struct bpf_insn *ins;
        char buf[100];
	int i, dlt = DLT_RAW;

	if (pcap_compile_nopcap(65535, dlt, &program, expr, 1,
				PCAP_NETMASK_UNKNOWN)) {
		return NULL;
	}

        if (program.bf_len > 63) {
               return NULL;
        }

	sprintf(bpf_program, "%d,", program.bf_len);
	ins = program.bf_insns;


	for (i = 0; i < program.bf_len-1; ++ins, ++i) {
                sprintf(buf, "%u %u %u %u,", ins->code, ins->jt, ins->jf, ins->k);
                strcat(bpf_program, buf);
        }

        sprintf(buf, "%u %u %u %u", ins->code, ins->jt, ins->jf, ins->k);
        strcat(bpf_program, buf);
	pcap_freecode(&program);
	return bpf_program;
}
*/
import "C"

import (
	"strings"
	"sync"
	"unsafe"

	"go.aporeto.io/gaia/protocols"
	"go.aporeto.io/trireme-lib/controller/internal/supervisor/iptablesctrl/pcap"
)

func getICMPv6() string {

	genString := func(icmpType string, icmpCode string) string {
		return "(icmp6[0] == " + icmpType + " and icmp6[1] == " + icmpCode + ")"
	}

	routerSolicitation := genString("133", "0")
	routerAdvertisement := genString("134", "0")
	neighborSolicitation := genString("135", "0")
	neighborAdvertisement := genString("136", "0")
	inverseNeighborSolicitation := genString("141", "0")
	inverseNeighborAdvertisement := genString("142", "0")

	s := []string{routerSolicitation,
		routerAdvertisement,
		neighborSolicitation,
		neighborAdvertisement,
		inverseNeighborSolicitation,
		inverseNeighborAdvertisement}

	return strings.Join(s, " or ")
}

var bpfLock sync.Mutex

func compileExprToBPF(expr string) string {
	bpfLock.Lock()
	defer bpfLock.Unlock()

	cExpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cExpr))

	bpfString := C.compileBPF(cExpr)

	return ("\"" + C.GoString(bpfString) + "\"")
}

func getBPFCode(icmpTypeCode string, policyRestriction []string) string {
	bytecode := compileExprToBPF(generateExpr(icmpTypeCode, policyRestriction))

	// bpf can return empty bytecodes as it is smart to know the expression
	// doesn't have a match. eg. 'icmp and icmp6'. In that case generate
	// and expression which doesn't match anything but bpf still generates byte code for.
	if bytecode == "\"\"" {
		bytecode = compileExprToBPF("icmp[0] > 5 and icmp[0] < 5")
	}

	return bytecode
}

func generateExpr(icmpTypeCode string, policyRestriction []string) string {

	processList := func(vs []string, f func(string) string) []string {
		vals := make([]string, len(vs))

		for i, v := range vs {
			vals[i] = f(v)
		}

		return vals
	}

	leafProcessElement := func(f func() string) string {
		return "(" + f() + ")"
	}

	genProto := func(val string) string {
		return leafProcessElement(func() string { return val })
	}

	genType := func(proto, icmpType string) string {

		switch strings.ToUpper(proto) {
		case protocols.L4ProtocolICMP:
			return leafProcessElement(func() string { return "icmp[0] == " + icmpType })
		default:
			return leafProcessElement(func() string { return "icmp6[0] == " + icmpType })
		}
	}

	genCodes := func(proto, val string) string {

		genCode := func(v string) string {

			switch splits := strings.Split(v, ":"); len(splits) {
			case 1:
				switch strings.ToUpper(proto) {
				case protocols.L4ProtocolICMP:
					return leafProcessElement(func() string { return "icmp[1] == " + v })
				default:
					return leafProcessElement(func() string { return "icmp6[1] == " + v })
				}
			default:
				min := splits[0]
				max := splits[1]

				switch strings.ToUpper(proto) {
				case protocols.L4ProtocolICMP:
					minExpr := leafProcessElement(func() string { return "icmp[1] >= " + min })
					maxExpr := leafProcessElement(func() string { return "icmp[1] <= " + max })
					return leafProcessElement(func() string { return minExpr + " and " + maxExpr })
				default:
					minExpr := leafProcessElement(func() string { return "icmp6[1] >= " + min })
					maxExpr := leafProcessElement(func() string { return "icmp6[1] <= " + max })
					return leafProcessElement(func() string { return minExpr + " and " + maxExpr })
				}
			}
		}

		splits := strings.Split(val, ",")
		vals := processList(splits, genCode)

		return leafProcessElement(func() string { return strings.Join(vals, "or") })
	}

	processSingleTypeCode := func(icmpTypeCode string) string {
		expr := ""
		splits := strings.Split(icmpTypeCode, "/")
		proto := splits[0]

		for i, val := range splits {
			switch i {
			case 0:
				expr = genProto(val)
			case 1:
				expr = leafProcessElement(func() string { return expr + " and " + genType(proto, val) })
			case 2:
				expr = leafProcessElement(func() string { return expr + " and " + genCodes(proto, val) })
			}
		}

		return expr
	}

	combined := []string{}
	bpfExprForPolicyRestriction := strings.Join(processList(policyRestriction, processSingleTypeCode), " or ")

	if bpfExprForPolicyRestriction != "" {
		bpfExprForPolicyRestriction = leafProcessElement(func() string { return bpfExprForPolicyRestriction })
		combined = []string{bpfExprForPolicyRestriction}
	}

	bpfExprForExtNet := processSingleTypeCode(icmpTypeCode)

	combined = append(combined, bpfExprForExtNet)
	return leafProcessElement(func() string { return strings.Join(combined, " and ") })
}

var icmpAllow = func() string {
	return compileExprToBPF(getICMPv6())
}

func allowICMPv6(cfg *ACLInfo) {
	cfg.ICMPv6Allow = icmpAllow()
}

func test() {
	pcap.Test()
}
