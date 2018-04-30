package tcbatch

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strconv"
	"strings"

	"github.com/alecthomas/template"
	//	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
)

const (
	qdisctemplate = `qdisc add dev {{.DeviceName}} {{if eq .Parent  "root" }} root {{else }} parent {{.Parent}} {{end}} handle {{.QdiscID}}: {{.QdiscType}}  {{"\n"}}`
	classtemplate = `class add dev {{.DeviceName}}  parent {{.Parent}}: classid {{.Parent}}:{{.ClassID}} {{.QdiscType}} {{if .AdditionalParams}} {{range .AdditionalParams}} {{.}} {{end}} {{end}}{{"\n"}}`

	//TODO: parametrize the flow key mark param
	filtertemplate     = `filter add dev {{.DeviceName}} parent {{.Parent}}: protocol ip {{if gt .Fw 0}} handle {{.Fw}} fw {{else}} {{if ge .Prio  0}} prio {{.Prio}} {{else}} handle {{.FilterID}} {{end}} {{end}} {{if .MarkMap}} flow key mark rshift 16 addend -256 baseclass 1:1 {{else}} {{if .U32match}} {{.ConvertU32}} {{end}}  action skbedit queue_mapping {{.QueueID}}{{end}}{{"\n"}}`
	metafiltertemplate = `filter add dev {{.DeviceName}} parent {{.Parent}}: handle {{.FilterID}} basic match {{if .MetaMatch}} {{.ConvertMeta}} {{end}} action skbedit queue_mapping {{.QueueID}}{{"\n"}}`
)

// Qdisc struct represents a qdisc(htb only) in the tcbatch (batched tc)
type Qdisc struct {
	DeviceName     string
	Parent         string
	QdiscID        string
	QdiscType      string
	DefaultClassID string
}

// Class represents a cgroup/prio class in tcbatch
type Class struct {
	DeviceName       string
	Parent           string
	ClassID          string
	QdiscType        string
	AdditionalParams []string
}

// U32match represent a U32 match in a filter
type U32match struct {
	matchsize string
	val       uint32
	mask      uint32
	offset    uint32
}

// Meta match struct used to represent meta matches supported by tc
type Meta struct {
	markType  string
	mask      uint32
	val       uint32
	condition string
}

// FilterSkbAction represent a Filter with skbedit action which modifies the queue of the outgoing packet
type FilterSkbAction struct {
	DeviceName string
	Parent     string
	FilterID   string
	U32match   *U32match
	MarkMap    bool
	MetaMatch  *Meta
	Prio       int
	Fw         int
	QueueID    string
	BaseClass  string
}

// TcBatch holds data required to serialize a tcbatch constrcuted using Qdisc, Class and FilterSkbAction structures
type TcBatch struct {
	buf             *bytes.Buffer
	DeviceName      string
	startQueue      uint16
	lastQueue       uint16
	CgroupHighBit   uint16
	CgroupStartMark uint16
}

// ConvertU32 is a helper function to convert a U32 struct to a tc command format for u32 matches
func (f FilterSkbAction) ConvertU32() string {
	return "u32 match " + f.U32match.matchsize + " 0x" + strconv.FormatUint(uint64(f.U32match.val), 16) + " 0x" + strconv.FormatUint(uint64(f.U32match.mask), 16) + " at " + strconv.FormatUint(uint64(f.U32match.offset), 10)
}

// ConvertMeta converts the metastruct into a tc command fragment
func (f FilterSkbAction) ConvertMeta() string {
	return "'meta(" + f.MetaMatch.markType + " mask" + strconv.Itoa(int(f.MetaMatch.mask)) + " " + f.MetaMatch.condition + " " + strconv.Itoa(int(f.MetaMatch.val)) + ")'"
}

// NewTCBatch creates a new tcbatch struct
func NewTCBatch(DeviceName string, startQueue uint16, lastQueue uint16, CgroupHighBit uint16, CgroupStartMark uint16) (*TcBatch, error) {
	if CgroupHighBit > 15 {
		return nil, fmt.Errorf("cgroup high bit has to between 0-15")
	}

	numQueues := lastQueue - startQueue + 1
	lastCgroupMark := CgroupStartMark + numQueues - 1

	if lastCgroupMark > 0xffff {
		return nil, fmt.Errorf("Cgroupstartmark has to high value")
	}

	if len(DeviceName) == 0 || len(DeviceName) > 16 {
		return nil, fmt.Errorf("Invalid DeviceName")
	}

	return &TcBatch{
		buf:             bytes.NewBuffer([]byte{}),
		startQueue:      startQueue,
		lastQueue:       lastQueue,
		DeviceName:      DeviceName,
		CgroupHighBit:   CgroupHighBit,
		CgroupStartMark: CgroupStartMark,
	}, nil
}

// Qdiscs converts qdisc struct to tc command strings
func (t *TcBatch) Qdiscs(qdiscs []Qdisc) (err error) {
	tmpl := template.New("Qdisc")

	tmpl, err = tmpl.Parse(qdisctemplate)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if err = tmpl.Execute(t.buf, qdisc); err != nil {
			return err
		}
	}

	return nil
}

// Classes converts class struct to tc class command strings
func (t *TcBatch) Classes(classes []Class) (err error) {
	tmpl := template.New("class")

	tmpl, err = tmpl.Parse(classtemplate)
	if err != nil {
		return err
	}
	for _, class := range classes {
		if err = tmpl.Execute(t.buf, class); err != nil {
			return err
		}
	}
	return nil
}

// Filters converts FilterSkbAction struct to tc filter commands
func (t *TcBatch) Filters(filters []FilterSkbAction, filterTemplate string) (err error) {
	tmpl := template.New("filters")
	tmpl, err = tmpl.Parse(filterTemplate)
	if err != nil {
		return err
	}

	for _, filter := range filters {
		if err = tmpl.Execute(t.buf, filter); err != nil {
			return err
		}
	}

	return nil
}

// String provides string function for tcbatch
func (t *TcBatch) String() string {
	return t.buf.String()
}

// BuildInputTCBatchCommand builds a list of tc commands for input processes
//////////////////////////////////////////////////////////////////////////////////////////////
// func (t *TcBatch) BuildInputTCBatchCommand() error {					    //
// 	qdisc := Qdisc{									    //
// 		DeviceName: t.DeviceName,						    //
// 		QdiscID:    "1",							    //
// 		QdiscType:  "htb",							    //
// 		Parent:     "root",							    //
// 	}										    //
// 	if err := t.Qdiscs([]Qdisc{qdisc}); err != nil {				    //
// 		return fmt.Errorf("Received error %s while parsing qdisc", err)		    //
// 	}										    //
// 	qdiscID := 1									    //
// 	handleID := 10									    //
// 	filters := make([]FilterSkbAction, t.numQueues)					    //
// 	for i := 0; i < int(t.numQueues); i++ {						    //
// 		filters[i] = FilterSkbAction{						    //
// 			DeviceName: t.DeviceName,					    //
// 			Parent:     strconv.Itoa(qdiscID),				    //
// 			FilterID:   strconv.Itoa(handleID),				    //
// 			QueueID:    strconv.Itoa(i),					    //
// 			Prio:       -1,							    //
// 			Cgroup:     false,						    //
// 			MetaMatch: &Meta{						    //
// 				markType:  "nf_mark",					    //
// 				mask:      0xffff,					    //
// 				val:       cgnetcls.Initialmarkval,			    //
// 				condition: "eq",					    //
// 			},								    //
// 		}									    //
// 		handleID = handleID + 10						    //
// 	}										    //
// 	if err := t.Filters(filters, metafiltertemplate); err != nil {			    //
// 		return fmt.Errorf("Received error %s while parsing filters", err)	    //
// 	}										    //
// 	return nil									    //
// }											    //
//////////////////////////////////////////////////////////////////////////////////////////////

// BuildOutputTCBatchCommand builds the list of tc commands required by the trireme-lib to setup a tc datapath
func (t *TcBatch) BuildOutputTCBatchCommand() error {
	numQueues := t.lastQueue - t.startQueue + 1

	qdisc := Qdisc{
		DeviceName:     t.DeviceName,
		QdiscID:        "1",
		QdiscType:      "htb",
		Parent:         "root",
		DefaultClassID: strconv.FormatUint(uint64(t.CgroupStartMark), 16),
	}

	if err := t.Qdiscs([]Qdisc{qdisc}); err != nil {
		return fmt.Errorf("Received error %s while parsing qdisc", err)
	}

	filterlist := []FilterSkbAction{
		{
			DeviceName: t.DeviceName,
			Parent:     "1",
			FilterID:   "1",
			QueueID:    "0",
			MarkMap:    true,
			Prio:       -1,
		},
	}

	if err := t.Filters(filterlist, filtertemplate); err != nil {
		return fmt.Errorf("Received error %s while parsing filters", err)
	}

	classes := make([]Class, numQueues)
	for i := 0; i < int(numQueues); i++ {
		classes[i] = Class{
			DeviceName:       t.DeviceName,
			Parent:           "1",
			ClassID:          strconv.FormatUint(uint64(i+1), 16),
			QdiscType:        "htb",
			AdditionalParams: []string{"rate", "100000mbit", "burst", "1200mbit"},
		}
	}

	if err := t.Classes(classes); err != nil {
		return fmt.Errorf("Received error %s while parsing classes", err)
	}

	qdiscs := make([]Qdisc, numQueues)
	initialqueueid := 10

	for i := 0; i < int(numQueues); i++ {
		qdiscs[i] = Qdisc{
			DeviceName: t.DeviceName,
			QdiscID:    strconv.Itoa(initialqueueid),
			QdiscType:  "htb",
			Parent:     "1:" + strconv.FormatUint(uint64(i+1), 16),
		}
		initialqueueid = initialqueueid + 10

	}

	if err := t.Qdiscs(qdiscs); err != nil {
		return fmt.Errorf("Received error %s while parsing qdisc", err)
	}

	filters := make([]FilterSkbAction, numQueues)
	qdiscID := 10
	for i := 0; i < int(numQueues); i++ {
		filters[i] = FilterSkbAction{
			DeviceName: t.DeviceName,
			Parent:     strconv.Itoa(qdiscID),
			FilterID:   strconv.Itoa(qdiscID),
			QueueID:    strconv.Itoa(int(t.startQueue) + i),
			Prio:       1,
			U32match: &U32match{
				matchsize: "u8",
				val:       0x40,
				mask:      0xf0,
				offset:    0,
			},
		}
		qdiscID = qdiscID + 10
	}
	if err := t.Filters(filters, filtertemplate); err != nil {
		return fmt.Errorf("Received error %s while parsing filters", err)
	}

	return nil
}

// Execute executes the commands built in the batch
func (t *TcBatch) Execute() error {
	ioutil.WriteFile("/tmp/tcout1", t.buf.Bytes(), 0644)
	path, err := exec.LookPath("tc")
	if err != nil {
		return fmt.Errorf("Received error %s while trying to locate tc binary", err)
	}
	for {
		if line, err := t.buf.ReadString('\n'); err != nil {
			break
		} else {
			params := strings.Fields(line)
			cmd := exec.Command(path, params...)
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("Error %s Executing Command %s", err, output)
			}

			continue

		}

	}

	return nil
}

// func main() {
// 	if t, err := NewTCBatch(255, "tunout", 1, 256); err != nil {
// 		fmt.Println(err)
// 		return
// 	} else {
// 		t.BuildOutputTCBatchCommand()
// 		fmt.Println(t)
// 	}
// 	//t.Execute()
// }
