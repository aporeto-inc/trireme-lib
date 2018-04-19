package policy

import (
	"strings"
	"sync"

	"github.com/aporeto-inc/trireme-lib/utils/tagging"
)

// TagStore stores the tags - it allows duplicate key values and
// fast indexing of the tags. A map would not be enough for this
// since does not support duplicate keys.
type TagStore struct {
	tags []string
	kv   map[string]map[string]bool
	sync.RWMutex
}

// NewTagStore creates a new TagStore
func NewTagStore() *TagStore {
	return &TagStore{
		[]string{},
		map[string]map[string]bool{},
	}
}

// NewTagStoreFromSlice creates a new tag store from a slice.
func NewTagStoreFromSlice(tags []string) *TagStore {
	kvMap := map[string]map[string]bool{}
	var k, v string
	for _, kv := range tags {
		err := tagging.Split(kv, &k, &v)
		if err != nil {
			continue
		}
		if _, ok := kvMap[k]; !ok {
			kvMap[k] = map[string]bool{}
		}
		kvMap[k][v] = true
	}
	return &TagStore{
		tags: tags,
		kv:   kvMap,
	}
}

// NewTagStoreFromMap creates a tag store from an input map
func NewTagStoreFromMap(tags map[string]string) *TagStore {
	taglist := make([]string, len(tags))
	kvMap := map[string]map[string]bool{}

	i := 0
	for k, v := range tags {
		taglist[i] = k + "=" + v
		i++

		if _, ok := kvMap[k]; !ok {
			kvMap[k] = map[string]bool{}
		}
		kvMap[k][v] = true
	}
	return &TagStore{
		tags: taglist,
		kv:   kvMap,
	}
}

// GetSlice returns the tagstore as a slice
func (t *TagStore) GetSlice() []string {
	return t.tags
}

// Copy copies a TagStore
func (t *TagStore) Copy() *TagStore {
	t.Lock()
	defer t.Unlock()

	c := make([]string, len(t.tags))
	copy(c, t.tags)

	return NewTagStoreFromSlice(c)
}

// GetValues retrieves all the values of the key/value set
func (t *TagStore) GetValues(key string) ([]string, bool) {

	t.RLock()
	defer t.RUnlock()

	valueMap, ok := t.kv[key]
	if !ok {
		return []string{}, false
	}

	slice := make([]string, len(valueMap))
	i := 0
	for v := range valueMap {
		slice[i] = v
		i++
	}
	return slice, true
}

// GetUnique retrieves the value of a string only if it is unique. It
// returns false if it is not found or if there are overlaps.
func (t *TagStore) GetUnique(key string) (string, bool) {

	t.RLock()
	defer t.RUnlock()

	valueMap, ok := t.kv[key]
	if !ok {
		return "", false
	}

	if len(valueMap) != 1 {
		return "", false
	}

	for v := range valueMap {
		return v, true
	}
	return "", false
}

// Merge merges tags from m into native tag store. if the key exists, the provided
// tag from m is ignored.
func (t *TagStore) Merge(m *TagStore) (merged int) {

	t.Lock()
	defer t.Unlock()

	var k, v string
	for _, kv := range m.GetSlice() {
		err := tagging.Split(kv, &k, &v)
		if err != nil {
			continue
		}

		if t.AppendKeyValue(k, v) {
			merged++
		}
	}
	return merged
}

// AppendKeyValue appends a key and value to the tag store if
// they don't exist.
func (t *TagStore) AppendKeyValue(key, value string) bool {

	t.Lock()
	defer t.Unlock()

	addToSlice := false

	if _, ok := t.kv[key]; !ok {
		addToSlice = true
		t.kv[key] = map[string]bool{}
	}

	if _, valueok := t.kv[key][value]; !valueok {
		t.kv[key][value] = true
		addToSlice = true
	}

	if addToSlice {
		t.tags = append(t.tags, key+"="+value)
	}

	return addToSlice
}

// String provides a string representation of tag store.
func (t *TagStore) String() string {
	t.RLock()
	defer t.RUnlock()

	return strings.Join(t.tags, " ")
}

// IsEmpty if no key value pairs exist.
func (t *TagStore) IsEmpty() bool {
	t.RLock()
	defer t.RUnlock()

	return len(t.tags) == 0
}
