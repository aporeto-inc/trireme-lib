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
	return t.Tags
}

// Copy copies an ExtendedMap
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

// AppendKeyValue appends a key and value to the tag store
func (t *TagStore) AppendKeyValue(key, value string) {
	t.Tags = append(t.Tags, key+"="+value)
}
