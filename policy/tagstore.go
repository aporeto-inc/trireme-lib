package policy

import (
	"strings"
)

// TagStore stores the tags - it allows duplicate key values
type TagStore struct {
	Tags []string
}

// NewTagStore creates a new TagStore
func NewTagStore() *TagStore {
	return &TagStore{[]string{}}
}

// NewTagStoreFromSlice creates a new tag store from a slice.
func NewTagStoreFromSlice(tags []string) *TagStore {
	return &TagStore{tags}
}

// NewTagStoreFromMap creates a tag store from an input map
func NewTagStoreFromMap(tags map[string]string) *TagStore {
	t := &TagStore{make([]string, len(tags))}
	i := 0
	for k, v := range tags {
		t.Tags[i] = k + "=" + v
		i++
	}
	return t
}

// GetSlice returns the tagstore as a slice
func (t *TagStore) GetSlice() []string {
	return append([]string{}, t.Tags...)
}

// Copy copies a TagStore
func (t *TagStore) Copy() *TagStore {

	c := make([]string, len(t.Tags))

	copy(c, t.Tags)

	return &TagStore{c}
}

// Get does a lookup in the list of tags
func (t *TagStore) Get(key string) (string, bool) {

	for _, kv := range t.Tags {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if key == parts[0] {
			return parts[1], true
		}
	}

	return "", false
}

// Merge merges tags from m into native tag store. if the key exists, the provided
// tag from m is ignored.
func (t *TagStore) Merge(m *TagStore) (merged int) {

	for _, kv := range m.Tags {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if _, ok := t.Get(parts[0]); !ok {
			t.AppendKeyValue(parts[0], parts[1])
			merged++
		}
	}
	return merged
}

// AppendKeyValue appends a key and value to the tag store
func (t *TagStore) AppendKeyValue(key, value string) {
	t.Tags = append(t.Tags, key+"="+value)
}

// String provides a string representation of tag store.
func (t *TagStore) String() string {
	return strings.Join(t.Tags, " ")
}

// IsEmpty if no key value pairs exist.
func (t *TagStore) IsEmpty() bool {
	return len(t.Tags) == 0
}
