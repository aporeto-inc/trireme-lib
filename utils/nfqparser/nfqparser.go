package nfqparser

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"sync"
)

// NFQParser holds nfqparser fields
type NFQParser struct {
	nfqStr string
	// NOTE: For unit test
	filePath string
	contents map[string]NFQLayout

	sync.Mutex
}

// NewNFQParser returns nfqparser handler
func NewNFQParser() *NFQParser {

	return &NFQParser{
		contents: make(map[string]NFQLayout),
		filePath: nfqFilePath,
	}
}

// Synchronize reads from file and parses it
func (n *NFQParser) Synchronize() error {

	n.Lock()
	defer n.Unlock()

	data, err := ioutil.ReadFile(n.filePath)
	if err != nil {
		return err
	}

	n.nfqStr = string(data)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)
		lineParts := strings.Fields(trimmedLine)
		newNFQ := makeNFQLayout(lineParts)

		n.contents[newNFQ.QueueNum] = newNFQ
	}

	return nil
}

// RetrieveByQueue returns layout for a specific queue number
func (n *NFQParser) RetrieveByQueue(queueNum string) *NFQLayout {

	n.Lock()
	defer n.Unlock()

	content, ok := n.contents[queueNum]
	if ok {
		return &content
	}

	return nil
}

// RetrieveByField returns layout in string representation
func (n *NFQParser) RetrieveByField(field Field) string {

	n.Lock()
	defer n.Unlock()

	var fieldStr string
	for _, key := range n.sortedKeys() {
		content := n.contents[key]
		switch field {
		case FieldPeerPortID:
			fieldStr = fieldStr + content.PeerPortID
		case FieldQueueTotal:
			fieldStr = fieldStr + content.QueueTotal
		case FieldCopyMode:
			fieldStr = fieldStr + content.CopyMode
		case FieldCopyRange:
			fieldStr = fieldStr + content.CopyRange
		case FieldQueueDropped:
			fieldStr = fieldStr + content.QueueDropped
		case FieldUserDropped:
			fieldStr = fieldStr + content.UserDropped
		case FieldIDSequene:
			fieldStr = fieldStr + content.IDSequene
		default:
			return fmt.Sprintf("Unknown field")
		}
	}

	return fieldStr
}

// String returns string renresentation of nfqueue data
func (n *NFQParser) String() string {

	n.Lock()
	defer n.Unlock()

	return n.nfqStr
}

func (n *NFQParser) sortedKeys() []string {

	var keys []string
	for key := range n.contents {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

func makeNFQLayout(data []string) NFQLayout {

	newNFQ := NFQLayout{}
	newNFQ.QueueNum = data[0]
	newNFQ.PeerPortID = data[1]
	newNFQ.QueueTotal = data[2]
	newNFQ.CopyMode = data[3]
	newNFQ.CopyRange = data[4]
	newNFQ.QueueDropped = data[5]
	newNFQ.UserDropped = data[6]
	newNFQ.IDSequene = data[7]

	return newNFQ
}
