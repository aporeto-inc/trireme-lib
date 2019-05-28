package nfqdatapath

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.aporeto.io/trireme-lib/controller/internal/supervisor/iptablesctrl"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
	"go.aporeto.io/trireme-lib/utils/portspec"
	"go.uber.org/zap"
)

type readSystemFiles interface {
	readOpenSockFD(pid string) []string
	readProcNetTCP() (inodeMap map[string]string, userMap map[string]map[string]bool, err error)
	getCgroupList() []string
	listCgroupProcesses(cgroupname string) ([]string, error)
}

type defaultRead struct{}

var readFiles readSystemFiles
var d *defaultRead
var lock sync.RWMutex

const (
	procNetTCPFile     = "/proc/net/tcp"
	uidFieldOffset     = 7
	inodeFieldOffset   = 9
	procHeaderLineNum  = 0
	portOffset         = 1
	ipPortOffset       = 1
	sockStateOffset    = 3
	sockListeningState = "0A"
	hexFormat          = 16
	integerSize        = 64
	minimumFields      = 2
)

func init() {
	lock.Lock()
	readFiles = d
	lock.Unlock()
}

func getUserName(uid string) (string, error) {

	u, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

func (d *Datapath) autoPortDiscovery() {
	for {
		d.findPorts()
		time.Sleep(2 * time.Second)
	}
}

// resync adds new port for the PU and removes the stale ports
func (d *Datapath) resync(newPortMap map[string]map[string]bool) {
	iptablesInstance := iptablesctrl.GetInstance()
	if iptablesInstance == nil {
		return
	}

	for k, vs := range d.puToPortsMap {
		m := newPortMap[k]

		for v := range vs {
			if m == nil || !m[v] {
				err := iptablesInstance.DeletePortFromPortSet(k, v)
				if err != nil {
					zap.L().Debug("autoPortDiscovery: Delete port set returned error", zap.Error(err))
				}
				// delete the port from contextIDFromTCPPort cache
				err = d.contextIDFromTCPPort.RemoveStringPorts(v)
				if err != nil {
					zap.L().Debug("autoPortDiscovery: can not remove port from cache", zap.Error(err))
				}
			}
		}
	}

	for k, vs := range newPortMap {
		m := d.puToPortsMap[k]
		for v := range vs {
			if m == nil || !m[v] {
				portSpec, err := portspec.NewPortSpecFromString(v, k)
				if err != nil {
					continue
				}
				d.contextIDFromTCPPort.AddPortSpec(portSpec)
				err = iptablesInstance.AddPortToPortSet(k, v)
				if err != nil {
					zap.L().Error("autoPortDiscovery: Failed to add port to portset", zap.String("context", k), zap.String("port", v))
				}
			}
		}
	}

	d.puToPortsMap = newPortMap
}

var lastRun time.Time

func (d *Datapath) findPorts() {
	lock.Lock()
	defer lock.Unlock()

	// Rate limit this function to run every 5 milliseconds
	if time.Since(lastRun) <= 5*time.Millisecond {
		return
	}

	lastRun = time.Now()

	cgroupList := readFiles.getCgroupList()

	newPUToPortsMap := map[string]map[string]bool{}
	inodeMap, userMap, err := readFiles.readProcNetTCP()
	if err != nil {
		zap.L().Error("autoPortDiscovery: /proc/net/tcp read failed with error", zap.Error(err))
		return
	}

	for _, cgroupPath := range cgroupList {
		/* cgroup is also the contextID */
		newMap := map[string]bool{}

		cgroup := filepath.Base(cgroupPath)

		// check if a PU exists with that contextID and is marked with auto port
		pu, err := d.puFromContextID.Get(cgroup)
		if err != nil {
			zap.L().Debug("autoPortDiscovery: failed to get PU from cgroup", zap.String("cgroupPath", cgroupPath), zap.String("cgroup", cgroup), zap.Error(err))
			continue
		}
		p := pu.(*pucontext.PUContext)

		// we skip AutoPort discovery if it is not enabled
		if !p.Autoport() {
			continue
		}

		procs, err := readFiles.listCgroupProcesses(cgroupPath)
		if err != nil {
			zap.L().Warn("autoPortDiscovery: Cgroup processes could not be retrieved", zap.String("cgroupPath", cgroupPath), zap.String("cgroup", cgroup), zap.Error(err))
			continue
		}
		zap.L().Debug("autoPortDiscovery: processes for cgroup detected", zap.String("cgroupPath", cgroupPath), zap.String("cgroup", cgroup), zap.String("id", p.ID()), zap.Strings("procs", procs))

		for _, proc := range procs {
			openSockFDs := readFiles.readOpenSockFD(proc)
			for _, sock := range openSockFDs {
				if inodeMap[sock] != "" {
					newMap[inodeMap[sock]] = true
				}
			}
		}

		newPUToPortsMap[cgroup] = newMap
	}

	for user, portMap := range userMap {
		if pu, err := d.puFromUser.Get(user); err == nil {
			contextID := pu.(*pucontext.PUContext).ID()
			newMap := map[string]bool{}

			for port := range portMap {
				newMap[port] = true
			}
			newPUToPortsMap[contextID] = newMap
		}
	}

	d.resync(newPUToPortsMap)
}

func (d *defaultRead) readProcNetTCP() (inodeMap map[string]string, userMap map[string]map[string]bool, err error) {

	buffer, err := ioutil.ReadFile(procNetTCPFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to read /proc/net/tcp file %s", err)
	}

	inodeMap = map[string]string{}
	userMap = map[string]map[string]bool{}

	s := string(buffer)

	for cnt, line := range strings.Split(s, "\n") {

		line := strings.Fields(line)
		// continue if not a valid line
		if len(line) < uidFieldOffset {
			continue
		}

		/* Look at socket which are in listening state only */
		if (cnt == procHeaderLineNum) || (line[sockStateOffset] != sockListeningState) {
			continue
		}

		/* Get the UID */
		uid := line[uidFieldOffset]
		inode := line[inodeFieldOffset]

		portString := ""
		{
			ipPort := strings.Split(line[ipPortOffset], ":")

			if len(ipPort) < minimumFields {
				zap.L().Warn("Failed to extract port")
				continue
			}

			portNum, err := strconv.ParseInt(ipPort[portOffset], hexFormat, integerSize)
			if err != nil {
				zap.L().Warn("failed to parse port ", zap.String("port", ipPort[portOffset]))
				continue
			}

			portString = strconv.Itoa(int(portNum))
		}

		inodeMap[inode] = portString

		// /proc/net/tcp file contains uid. Conversion to
		// userName is required as they are keys to lookup tables.
		userName, err := getUserName(uid)
		if err != nil {
			zap.L().Debug("Error converting to username", zap.Error(err))
			continue
		}

		portMap := userMap[userName]
		if portMap == nil {
			portMap = map[string]bool{}
		}
		portMap[portString] = true
		userMap[userName] = portMap
	}

	return inodeMap, userMap, nil
}

func (d *defaultRead) readOpenSockFD(pid string) []string {
	var inodes []string
	fdPath := "/proc/" + pid + "/fd/"

	buffer, err := ioutil.ReadDir(fdPath)
	if err != nil {
		zap.L().Warn("Failed to read", zap.String("file", fdPath), zap.Error(err))
		return nil
	}

	for _, f := range buffer {
		link, err := os.Readlink(fdPath + f.Name())

		if err != nil {
			zap.L().Warn("Failed to read", zap.String("file", fdPath+f.Name()))
			continue
		}
		if strings.Contains(link, "socket:") {
			socketInode := strings.Split(link, ":")

			if len(socketInode) < minimumFields {
				zap.L().Warn("Failed to parse socket inodes")
				continue
			}

			inodeString := socketInode[1]
			inodeString = strings.TrimSuffix(inodeString, "]")
			inodeString = strings.TrimPrefix(inodeString, "[")

			inodes = append(inodes, inodeString)
		}
	}
	return inodes
}

func (d *defaultRead) getCgroupList() []string {
	return cgnetcls.GetCgroupList()
}

func (d *defaultRead) listCgroupProcesses(cgroupname string) ([]string, error) {
	return cgnetcls.ListCgroupProcesses(cgroupname)
}
