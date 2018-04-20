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
	Tags    []string
	tagsMap map[string]map[string]bool
	lock    sync.RWMutex
}

// NewTagStore creates a new TagStore
func NewTagStore() *TagStore {
	return &TagStore{
		Tags:    []string{},
		tagsMap: map[string]map[string]bool{},
		lock:    sync.RWMutex{},
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
		Tags:    tags,
		tagsMap: kvMap,
		lock:    sync.RWMutex{},
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
		Tags:    taglist,
		tagsMap: kvMap,
		lock:    sync.RWMutex{},
	}
}

// GetSlice returns the tagstore as a slice
func (t *TagStore) GetSlice() []string {
	return t.Tags
}

// Copy copies a TagStore
func (t *TagStore) Copy() *TagStore {
	t.lock.Lock()
	defer t.lock.Unlock()

	c := make([]string, len(t.Tags))
	copy(c, t.Tags)

	return NewTagStoreFromSlice(c)
}

// GetValues retrieves all the values of the key/value set
func (t *TagStore) GetValues(key string) ([]string, bool) {

	t.lock.RLock()
	defer t.lock.RUnlock()

	valueMap, ok := t.tagsMap[key]
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

	t.lock.RLock()
	defer t.lock.RUnlock()

	valueMap, ok := t.tagsMap[key]
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

// GetFirstFromSlice retrieves the first matching key/value
func (t *TagStore) GetFirstFromSlice(key string) (string, bool) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	for _, kv := range t.Tags {
		if strings.HasPrefix(kv, key) {
			return kv[len(key)+1:], true
		}
	}
	return "", false
}

// Merge merges tags from m into native tag store. if the key exists, the provided
// tag from m is ignored.
func (t *TagStore) Merge(m *TagStore) (merged int) {

	t.lock.Lock()
	defer t.lock.Unlock()

	var k, v string
	for _, kv := range m.GetSlice() {
		err := tagging.Split(kv, &k, &v)
		if err != nil {
			continue
		}

		if t.appendKeyValue(k, v) {
			merged++
		}
	}
	return merged
}

// AppendKeyValue appends a key and value to the tag store if
// they don't exist.
func (t *TagStore) AppendKeyValue(key, value string) bool {

	t.lock.Lock()
	defer t.lock.Unlock()

	return t.appendKeyValue(key, value)
}

// AppendKeyValue appends a key and value to the tag store if
// they don't exist.
func (t *TagStore) appendKeyValue(key, value string) bool {

	addToSlice := false

	if t.tagsMap == nil {
		t.tagsMap = map[string]map[string]bool{}
	}

	if _, ok := t.tagsMap[key]; !ok {
		addToSlice = true
		t.tagsMap[key] = map[string]bool{}
	}

	if _, valueok := t.tagsMap[key][value]; !valueok {
		t.tagsMap[key][value] = true
		addToSlice = true
	}

	if addToSlice {
		t.Tags = append(t.Tags, key+"="+value)
	}

	return addToSlice
}

// String provides a string representation of tag store.
func (t *TagStore) String() string {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return strings.Join(t.Tags, " ")
}

// IsEmpty if no key value pairs exist.
func (t *TagStore) IsEmpty() bool {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return len(t.Tags) == 0
}
