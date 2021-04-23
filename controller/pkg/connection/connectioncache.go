package connection

import (
	"sync"
)

//TCPCache is an interface to store tcp connections
//keyed with the string.
type TCPCache interface {
	Put(string, *TCPConnection)
	Get(string) (*TCPConnection, bool)
	Remove(string)
	Len() int
}

type tcpCache struct {
	m map[string]*TCPConnection
	sync.RWMutex
}

//NewTCPConnectionCache initializes the tcp connection cache
func NewTCPConnectionCache() TCPCache {
	return &tcpCache{m: map[string]*TCPConnection{}}
}

//Put stores the connection object with the key string
func (c *tcpCache) Put(key string, conn *TCPConnection) {
	c.Lock()
	c.m[key] = conn
	c.Unlock()
}

//Get gets the tcp connection object keyed with the key string
func (c *tcpCache) Get(key string) (*TCPConnection, bool) {
	c.RLock()
	conn, exists := c.m[key]
	c.RUnlock()

	return conn, exists
}

//Remove remove the connection object keyed with the key string
func (c *tcpCache) Remove(key string) {
	c.Lock()
	delete(c.m, key)
	c.Unlock()
}

func (c *tcpCache) Len() int {
	c.Lock()
	size := len(c.m)
	c.Unlock()

	return size
}
