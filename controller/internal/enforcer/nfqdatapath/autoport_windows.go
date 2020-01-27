// +build windows

package nfqdatapath

func (d *defaultRead) readProcNetTCP() (inodeMap map[string]string, userMap map[string]map[string]bool, err error) {

	inodeMap = map[string]string{}
	userMap = map[string]map[string]bool{}

	return inodeMap, userMap, nil
}

func (d *defaultRead) readOpenSockFD(pid string) []string {
	var inodes []string

	return inodes
}

func (d *defaultRead) getCgroupList() []string {
	return []string{}
}

func (d *defaultRead) listCgroupProcesses(cgroupname string) ([]string, error) {
	return []string{}, nil
}
