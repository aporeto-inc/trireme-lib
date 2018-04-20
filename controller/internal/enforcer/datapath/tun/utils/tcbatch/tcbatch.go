package tcbatch

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/alecthomas/template"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
)

const (
	qdisctemplate = `qdisc add dev {{.DeviceName}} {{if eq .Parent  "root" }} root {{else }} parent {{.Parent}} {{end}} handle {{.QdiscID}}: {{.QdiscType}}  {{"\n"}}`
	classtemplate = `class add dev {{.DeviceName}}  parent {{.Parent}}: classid {{.Parent}}:{{.ClassId}} {{.QdiscType}} {{if .AdditionalParams}} {{range .AdditionalParams}} {{.}} {{end}} {{end}}{{"\n"}}`

	filtertemplate     = `filter add dev {{.DeviceName}} parent {{.Parent}}: protocol ip {{if gt .Fw 0}} handle {{.Fw}} fw {{else}} {{if ge .Prio  0}} prio {{.Prio}} {{else}} handle {{.FilterID}}: {{end}} {{end}}{{if .U32match}} {{.ConvertU32}} {{end}}  {{if .Cgroup}} cgroup {{end}} action skbedit queue_mapping {{.QueueID}}{{"\n"}}`
	metafiltertemplate = `filter add dev {{.DeviceName}} parent {{.Parent}}: handle {{.FilterID}} basic match {{if .MetaMatch}} {{.ConvertMeta}} {{end}} action skbedit queue_mapping {{.QueueID}}{{"\n"}}`
)

// Qdisc strcut represents a qdisc(htb only) in the tcbatch (batched tc)
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
	ClassId          string
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
	MetaMatch  *Meta
	Cgroup     bool
	Prio       int
	Fw         int
	QueueID    string
}

// tcBatch holds data required to serialize a tcbatch constrcuted using Qdisc, Class and FilterSkbAction structures
type tcBatch struct {
	buf             *bytes.Buffer
	numQueues       uint16
	DeviceName      string
	CgroupHighBit   uint16
	CgroupStartMark uint16
}

// ConvertU32 is a helper fucntion to convert a U32 struct to a tc command format for u32 matches
func (f FilterSkbAction) ConvertU32() string {
	return "u32 match " + f.U32match.matchsize + " 0x" + strconv.FormatUint(uint64(f.U32match.val), 16) + " 0x" + strconv.FormatUint(uint64(f.U32match.mask), 16) + " at " + strconv.FormatUint(uint64(f.U32match.offset), 10)
}

func (m FilterSkbAction) ConvertMeta() string {
	return "'meta(" + m.MetaMatch.markType + " mask" + strconv.Itoa(int(m.MetaMatch.mask)) + " " + m.MetaMatch.condition + " " + strconv.Itoa(int(m.MetaMatch.val)) + ")'"
}

// NewTCBatch creates a new tcbatch struct
func NewTCBatch(numQueues uint16, DeviceName string, CgroupHighBit uint16, CgroupStartMark uint16) (*tcBatch, error) {
	if numQueues > 255 {
		return nil, fmt.Errorf("Invalid Queue Num. Queue num has to be less than 255")
	}

	if CgroupHighBit > 15 {
		return nil, fmt.Errorf("cgroup high bit has to between 0-15")
	}
	if CgroupStartMark+numQueues+1 > ((1 << 16) - 1) {
		return nil, fmt.Errorf("Cgroupstartmark has to high value")
	}

	if len(DeviceName) == 0 || len(DeviceName) > 16 {
		return nil, fmt.Errorf("Invalid DeviceName")
	}
	return &tcBatch{
		buf:             bytes.NewBuffer([]byte{}),
		numQueues:       numQueues + 1,
		DeviceName:      DeviceName,
		CgroupHighBit:   CgroupHighBit,
		CgroupStartMark: CgroupStartMark,
	}, nil
}

// Qdiscs converts qdisc struct to tc command strings
func (t *tcBatch) Qdiscs(qdiscs []Qdisc) (err error) {
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
func (t *tcBatch) Classes(classes []Class) (err error) {
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
func (t *tcBatch) Filters(filters []FilterSkbAction, filterTemplate string) (err error) {
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
func (t *tcBatch) String() string {
	return t.buf.String()
}

// BuildInputTCBatchCommand builds a list of tc commands for input processes
func (t *tcBatch) BuildInputTCBatchCommand() error {
	qdisc := Qdisc{
		DeviceName: t.DeviceName,
		QdiscID:    "1",
		QdiscType:  "htb",
		Parent:     "root",
	}
	if err := t.Qdiscs([]Qdisc{qdisc}); err != nil {
		return fmt.Errorf("Received error %s while parsing qdisc", err)
	}
	qdiscID := 1
	handleID := 10
	filters := make([]FilterSkbAction, t.numQueues)
	for i := 0; i < int(t.numQueues); i++ {
		filters[i] = FilterSkbAction{
			DeviceName: t.DeviceName,
			Parent:     strconv.Itoa(qdiscID),
			FilterID:   strconv.Itoa(handleID),
			QueueID:    strconv.Itoa(i),
			Prio:       -1,
			Cgroup:     false,
			MetaMatch: &Meta{
				markType:  "nf_mark",
				mask:      0xffff,
				val:       cgnetcls.Initialmarkval,
				condition: "eq",
			},
		}
		handleID = handleID + 10
	}
	if err := t.Filters(filters, metafiltertemplate); err != nil {
		return fmt.Errorf("Received error %s while parsing filters", err)
	}
	return nil
}

// BuildOutputTCBatchCommand builds the list of tc commands required by the trireme-lib to setup a tc datapath
func (t *tcBatch) BuildOutputTCBatchCommand() error {
	numQueues := t.numQueues
	//qdiscs := make([]Qdisc, numQueues+1)
	qdisc := Qdisc{
		DeviceName: t.DeviceName,
		QdiscID:    "1",
		QdiscType:  "htb",
		Parent:     "root",
		// DefaultClassID: strconv.FormatUint(uint64(t.CgroupStartMark)+uint64(t.numQueues-1), 16),
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
			Prio:       -1,
			Cgroup:     true,
		},
		// {
		// 	DeviceName: t.DeviceName,
		// 	Parent:     "1",
		// 	FilterID:   "1",
		// 	QueueID:    "0",
		// 	Prio:       -1,
		// 	Cgroup:     false,
		// 	Fw:         cgnetcls.Initialmarkval - 2,
		// },
	}
	if err := t.Filters(filterlist, filtertemplate); err != nil {
		return fmt.Errorf("Received error %s while parsing filters", err)
	}

	classes := make([]Class, numQueues)
	for i := 0; i < int(numQueues); i++ {
		classes[i] = Class{
			DeviceName:       t.DeviceName,
			Parent:           "1",
			ClassId:          strconv.FormatUint(uint64(t.CgroupStartMark)+uint64(i), 16),
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
			Parent:     "1:" + strconv.FormatUint(uint64(t.CgroupStartMark)+uint64(i), 16),
		}
		initialqueueid = initialqueueid + 10

	}

	if err := t.Qdiscs(qdiscs); err != nil {
		return fmt.Errorf("Received error %s while parsing qdisc", err)
	}
	filters := make([]FilterSkbAction, numQueues-1)
	qdiscID := 10
	for i := 1; i < int(numQueues); i++ {
		filters[i-1] = FilterSkbAction{
			DeviceName: t.DeviceName,
			Parent:     strconv.Itoa(qdiscID),
			FilterID:   strconv.Itoa(qdiscID),
			QueueID:    strconv.Itoa(i),
			Prio:       1,
			Cgroup:     false,
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
	//Default filter and action set to queue 0
	filter := FilterSkbAction{
		DeviceName: t.DeviceName,
		Parent:     strconv.Itoa(qdiscID),
		FilterID:   strconv.Itoa(qdiscID),
		QueueID:    "0",
		Prio:       1,
		Cgroup:     false,
		U32match: &U32match{
			matchsize: "u8",
			val:       0x40,
			mask:      0xf0,
			offset:    0,
		},
	}
	if err := t.Filters([]FilterSkbAction{filter}, filtertemplate); err != nil {
		return fmt.Errorf("Received error %s while parsing filters", err)
	}
	return nil
}

// Execute executes the commands built in the batch
func (t *tcBatch) Execute() error {
	for {
		if line, err := t.buf.ReadString('\n'); err != nil {
			break
		} else {
			path, err := exec.LookPath("tc")
			if err != nil {
				return fmt.Errorf("Received error %s while trying to locate tc binary", err)
			}

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
