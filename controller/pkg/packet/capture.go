package packet

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"time"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.uber.org/zap"
)

type captureFlow struct {
	flow Flow
	time time.Time
}

type Flow struct {
	SrcIP   string `json:"src"`
	DstIP   string `json:"dst"`
	SrcPort uint16 `json:"sport"`
	DstPort uint16 `json:"dport"`
	Proto   uint8  `json:"proto"`
	Time    int    `json:"time"`
}

var lastUpdatedFlow *captureFlow
var threadNumToFlow []*captureFlow
var writePCAP *os.File

func InitCapture(numQueues uint16) {
	var err error

	pcapFile := "/var/lib/aporeto/capture" + os.Getenv(constants.EnvLogID)
	writePCAP, err = os.OpenFile(pcapFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660)

	threadNumToFlow = make([]*captureFlow, numQueues)
	if err != nil {
		return
	}

	go updateFlows()
}

func updateFlows() {
	var lastModified time.Time
	var jsonFile *os.File
	var err error
	var flowLocal *captureFlow

	for ; ; time.Sleep(5 * time.Second) {
		if jsonFile != nil {
			jsonFile.Close()
			jsonFile = nil
		}

		if jsonFile == nil {
			jsonFile, err = os.Open("/var/lib/aporeto/inputflow.json")
			if err != nil {
				continue
			}
		}

		fileInfo, err := jsonFile.Stat()
		if err != nil {
			continue
		}

		modTime := fileInfo.ModTime()

		if modTime == lastModified {
			continue
		}

		lastModified = modTime
		byteVal, err := ioutil.ReadAll(jsonFile)

		if err != nil {
			zap.L().Error("Read json returned error", zap.Error(err))
			continue
		}

		flowLocal = new(captureFlow)
		err = json.Unmarshal(byteVal, &flowLocal.flow)
		if err != nil {
			zap.L().Error("error json unmarshal", zap.Error(err))
			continue
		}

		flowLocal.time = time.Now()
		lastUpdatedFlow = flowLocal
	}
}

func writeCapture(buffer []byte) {

	if writePCAP != nil {

		// Add fake ethernet header
		var header []byte = []byte{0xab, 0xcd, 0xef, 0x00, 0x01, 0x02, 0xbc, 0xcd, 0xef, 0x00, 0x01, 0x02, 0x08, 0x00}

		if _, err := writePCAP.WriteString(hex.Dump(append(header, buffer...))); err != nil {
			zap.L().Error("Could not write pcap file")
		}
	}
}

func (p *Packet) DebugCapture(buffer []byte, queueNum uint16) {

	// Safety check
	if int(queueNum) >= len(threadNumToFlow) {
		return
	}

	// Do not write on the shared data structure if the element has not changed
	if threadNumToFlow[queueNum] != lastUpdatedFlow {
		threadNumToFlow[queueNum] = lastUpdatedFlow
	}

	localFlow := threadNumToFlow[queueNum]

	if localFlow == nil || time.Since(localFlow.time) > time.Duration(localFlow.flow.Time)*time.Second {
		return
	}

	pktSrcIP := p.SourceAddress.String()
	pktDstIP := p.DestinationAddress.String()

	// Match either of the flow

	if pktSrcIP == localFlow.flow.SrcIP &&
		p.SourcePort == localFlow.flow.SrcPort &&
		pktDstIP == localFlow.flow.DstIP &&
		p.DestinationPort == localFlow.flow.DstPort &&
		p.IPProto == localFlow.flow.Proto {

		writeCapture(buffer)
	}

	if pktSrcIP == localFlow.flow.DstIP &&
		p.SourcePort == localFlow.flow.DstPort &&
		pktDstIP == localFlow.flow.SrcIP &&
		p.DestinationPort == localFlow.flow.SrcPort &&
		p.IPProto == localFlow.flow.Proto {

		writeCapture(buffer)
	}
}
