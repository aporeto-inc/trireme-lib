// +build !windows

package nfqdatapath

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"strings"

	"go.aporeto.io/enforcerd/trireme-lib/utils/cgnetcls"
	"go.uber.org/zap"
)

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

func getUserName(uid string) (string, error) {

	u, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return u.Username, nil
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
				zap.L().Warn("failed to parse port", zap.String("port", ipPort[portOffset]))
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
