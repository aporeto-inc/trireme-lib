package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TagStore stores the tags - it allows duplicate key values
type TagStore struct {
	// Could have used a map of maps, but I want to preserve the insert order of the key=value.
	tags map[string][]string
}

// UnmarshalJSON custom unmarshal bytes to tagstore
func (t *TagStore) UnmarshalJSON(b []byte) error {
	var s []string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	// create new map because I expect only the unmarshalled data be in the storen
	t.tags = map[string][]string{}
	t.MergeSlice(s)
	return nil
}

// MarshalJSON custom marshal tagstore to bytes
func (t *TagStore) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.GetSlice())
}

// NewTagStore creates a new TagStore
func NewTagStore() *TagStore {
	return &TagStore{map[string][]string{}}
}

// NewTagStoreFromSlice creates a new tag store from a slice.
func NewTagStoreFromSlice(tags []string) *TagStore {
	tagStore := NewTagStore()
	tagStore.MergeSlice(tags)
	return tagStore
}

// NewTagStoreFromMap creates a tag store from an input map
func NewTagStoreFromMap(tags map[string]string) *TagStore {
	tagStore := NewTagStore()
	tagStore.MergeMap(tags)
	return tagStore
}

// GetSlice returns the tagstore as a slice
func (t *TagStore) GetSlice() []string {
	slice := []string{}
	for key, values := range t.tags {
		if len(values) == 0 {
			slice = append(slice, key)
		} else {
			for _, value := range values {
				slice = append(slice, fmt.Sprintf("%s=%s", key, value))
			}
		}
	}
	return slice
}

// Copy copies a TagStore
func (t *TagStore) Copy() *TagStore {
	tagStore := NewTagStore()
	tagStore.MergeSlice(t.GetSlice())
	return tagStore
}

// Get does a lookup in the list of tags
func (t *TagStore) Get(key string) (string, bool) {
	// This function doesn't handle duplicate keys, so we grab the first one that was inserted.
	// This is how the previous code would have worked when it used a slice
	if _, ok := t.tags[key]; ok {
		values := t.tags[key]
		if len(values) != 0 {
			return values[0], true
		}
	}
	return "", false
}

// Merge merges tags from m into native tag store.
func (t *TagStore) Merge(m *TagStore) {
	for key, values := range m.tags {
		if len(values) == 0 {
			t.AppendKeyValue(key, "")
		} else {
			for _, value := range values {
				t.AppendKeyValue(key, value)
			}
		}
	}
}

// MergeSlice merges slice of tags into the tag store.
func (t *TagStore) MergeSlice(tags []string) {
	for _, tag := range tags {
		t.Add(tag)
	}
}

// MergeMap merges map of tags into the tag store.
func (t *TagStore) MergeMap(tags map[string]string) {
	for key, value := range tags {
		t.AppendKeyValue(key, value)
	}
}

// Add appends tag to the tag store
func (t *TagStore) Add(tag string) {
	parts := strings.Split(tag, "=")
	switch len(parts) {
	case 1:
		t.AppendKeyValue(tag, "")
	case 2:
		t.AppendKeyValue(parts[0], parts[1])
	}
}

// AppendKeyValue appends a key and value to the tag store
func (t *TagStore) AppendKeyValue(key, value string) {
	if _, ok := t.tags[key]; !ok {
		t.tags[key] = []string{}
	}
	// Dont add empty string to the slice
	if len(value) == 0 {
		return
	}
	// Only add if it doesn't exist
	for _, v := range t.tags[key] {
		if v == value {
			return
		}
	}
	t.tags[key] = append(t.tags[key], value)
}

// String provides a string representation of tag store.
func (t *TagStore) String() string {
	builder := strings.Builder{}
	for key, values := range t.tags {
		if builder.Len() != 0 {
			builder.WriteString(" ")
		}
		if len(values) == 0 {
			builder.WriteString(key)
		} else {
			for index, value := range values {
				if index != 0 {
					builder.WriteString(" ")
				}
				builder.WriteString(key)
				builder.WriteString("=")
				builder.WriteString(value)
			}
		}
	}
	return builder.String()
}

// IsEmpty if no key value pairs exist.
func (t *TagStore) IsEmpty() bool {
	return len(t.tags) == 0
}

// GetKeys returns the unique keys for this tag store
func (t *TagStore) GetKeys() []string {
	keys := []string{}
	for k := range t.tags {
		keys = append(keys, k)
	}
	return keys
}

// RemoveTagsByKeys removes all tags by key
func (t *TagStore) RemoveTagsByKeys(keys []string) {
	for _, k := range keys {
		delete(t.tags, k)
	}
}
