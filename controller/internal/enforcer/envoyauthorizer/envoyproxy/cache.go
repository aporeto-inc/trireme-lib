package envoyproxy

import "sync"

type kvcache struct {
	sync.RWMutex
	cache map[string]interface{}
}

// NewkvCache allocates a new keyVal cache struct
func newkvCache() *kvcache {
	return &kvcache{
		cache: make(map[string]interface{}),
	}
}

func (kv *kvcache) load(key string) (value interface{}, ok bool) {
	kv.RLock()
	result, ok := kv.cache[key]
	kv.RUnlock()
	return result, ok
}

func (kv *kvcache) delete(key string) {
	kv.Lock()
	delete(kv.cache, key)
	kv.Unlock()
}

func (kv *kvcache) store(key string, value interface{}) {
	kv.Lock()
	kv.cache[key] = value
	kv.Unlock()
}
