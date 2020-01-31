package rpcwrapper

import (
	"reflect"
	"sync"

	"github.com/ugorji/go/codec"
)

type msgpackHandle struct {
	h *codec.MsgpackHandle

	sync.Mutex
}

func newMsgpackHandle() *msgpackHandle {

	h := &codec.MsgpackHandle{}
	h.WriteExt = true
	h.Canonical = true
	h.MapType = reflect.ValueOf(map[string]interface{}{}).Type()
	h.TypeInfos = codec.NewTypeInfos([]string{"msgpack"})

	return &msgpackHandle{h: h}
}

func (m *msgpackHandle) handler() *codec.MsgpackHandle {
	m.Lock()
	defer m.Unlock()

	return m.h
}
