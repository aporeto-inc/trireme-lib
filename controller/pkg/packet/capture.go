package packet

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.uber.org/zap"
)

type Flows struct {
	sync.RWMutex
	Flows []Flow `json:"flows"`
}

type Flow struct {
	SrcIP         string `json:"src"`
	DstIP         string `json:"dst"`
	SrcPort       uint16 `json:"sport"`
	DstPort       uint16 `json:"dport"`
	Proto         uint8  `json:"proto"`
	Packets       uint16 `json:"packets"`
	packetsDumped uint16
}

var flows Flows
var lastUpdated time.Time
var writePCAP *os.File

func init() {
	var err error
	lastUpdated = time.Now()
	updateFlows()
	pcapFile := "/var/lib/aporeto/capture" + os.Getenv(constants.EnvLogID)
	writePCAP, err = os.OpenFile(pcapFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		return
	}

	go updateFlows()
}

func updateFlows() {
	var lastModified time.Time
	var jsonFile *os.File
	var err error

	for ; ; time.Sleep(5 * time.Second) {
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

		byteVal, err := ioutil.ReadAll(jsonFile)
		if err != nil {
			zap.L().Error("Read json returned error", zap.Error(err))
			continue
		}

		flows.Lock()
		err = json.Unmarshal(byteVal, &flows)
		flows.Unlock()

		if err != nil {
			zap.L().Error("error json unmarshal", zap.Error(err))
			continue
		}

		lastModified = modTime
	}
}

func writeCapture(buffer []byte, index int) {
	if writePCAP != nil && flows.Flows[index].packetsDumped < flows.Flows[index].Packets {

		var header []byte = []byte{0xab, 0xcd, 0xef, 0x00, 0x01, 0x02, 0xbc, 0xcd, 0xef, 0x00, 0x01, 0x02, 0x08, 0x00}

		if _, err := writePCAP.WriteString(hex.Dump(append(header, buffer...))); err != nil {
			zap.L().Error("Could not write pcap file")
		}

		flows.Flows[index].packetsDumped += 1
	}
}

func (p *Packet) DebugCapture(buffer []byte) {

	flows.RLock()
	defer flows.RUnlock()

	for i := 0; i < len(flows.Flows); i++ {
		pktSrcIP := p.SourceAddress.String()
		pktDstIP := p.DestinationAddress.String()

		// Match either of the flow

		if pktSrcIP == flows.Flows[i].SrcIP &&
			p.SourcePort == flows.Flows[i].SrcPort &&
			pktDstIP == flows.Flows[i].DstIP &&
			p.DestinationPort == flows.Flows[i].DstPort &&
			p.IPProto == flows.Flows[i].Proto {

			writeCapture(buffer, i)
		}

		if pktSrcIP == flows.Flows[i].DstIP &&
			p.SourcePort == flows.Flows[i].DstPort &&
			pktDstIP == flows.Flows[i].SrcIP &&
			p.DestinationPort == flows.Flows[i].SrcPort &&
			p.IPProto == flows.Flows[i].Proto {

			writeCapture(buffer, i)
		}
	}
}
