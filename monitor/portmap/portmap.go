package portmap

import "strconv"

//ProxyPortMap -- proxy portmap struct
type ProxyPortMap struct {
	portMap chan string
}

//New -- Create a new port map
func New(start, size int) *ProxyPortMap {
	portchan := make(chan string, size)
	for i := start; i < (start + size); i++ {
		portchan <- strconv.FormatInt(int64(i), 10)
	}
	return &ProxyPortMap{
		portMap: portchan,
	}
}

//GetPort -- GetPort from global Pool
func (p *ProxyPortMap) GetPort() string {
	return <-p.portMap
}

//ReleasePort -- Return port back to global pool
func (p *ProxyPortMap) ReleasePort(port string) {
	p.portMap <- port
}
