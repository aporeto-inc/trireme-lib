package main

/*
#cgo LDFLAGS: -lpam -fPIC
#include <security/pam_appl.h>
#include <stdlib.h>
char *get_user(pam_handle_t *pamh);
char *get_ruser(pam_handle_t *pamh);
char *get_rhost(pam_handle_t *pamh);
char *get_service(pam_handle_t *pam_h);
void initLog() ;
int is_system_user(char *user);
int is_root(char *user);
*/
import "C"
import (
	"bufio"
	"fmt"
	"log/syslog"
	"os"
	"os/user"
	"strings"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/remoteapi/client"
)

// nolint
//export pam_sm_open_session
func pam_sm_open_session(pamh *C.pam_handle_t, flags, argc int, argv **C.char) C.int {
	C.initLog()
	username := C.get_user(pamh)
	service := C.get_service(pamh)
	metadatamap := []string{}
	goUserName := C.GoString(username)
	userstring := "user=" + goUserName
	metadatamap = append(metadatamap, userstring)
	slog, _ := syslog.New(syslog.LOG_ALERT|syslog.LOG_AUTH, "mypam")
	defer func() {
		_ = slog.Close()
	}()
	userhandle, err := user.Lookup(goUserName)
	if err != nil {
		slog.Alert("Invalid username" + goUserName)
	}
	if groups, err := userhandle.GroupIds(); err != nil {
		slog.Alert("Unable to get group list" + err.Error())
	} else {
		for _, group := range groups {
			//metadatamap = append(metadatamap, "groupid_"+strconv.Itoa(i)+"="+group)
			// if grpEntry, err := user.LookupGroup(group); err == nil {
			// 	metadatamap = append(metadatamap, "groupname"+strconv.Itoa(i)+"="+grpEntry.Name)
			// } else {
			// 	slog.Alert("HERE6" + err.Error())
			// }
			//hack lookupgroup is returning errors
			if groupName, err := findgroupname(group); err == nil {
				metadatamap = append(metadatamap, "groupname="+groupName)
			}

		}
	}
	if service != nil {
		metadatamap = append(metadatamap, "SessionType="+C.GoString(service))
	} else {
		metadatamap = append(metadatamap, "SessionType=login")
	}

	request := &common.EventInfo{
		PUType:    common.UIDLoginPU,
		PUID:      goUserName,
		Name:      "login-" + goUserName,
		PID:       int32(os.Getpid()),
		Tags:      metadatamap,
		EventType: "start",
	}

	if C.is_root(username) == 1 {
		//Do nothing this is login shell account
	} else {
		//Do something

		client, err := client.NewClient(common.TriremeSocket)
		if err != nil {
			return C.PAM_SUCCESS
		}

		slog.Alert("Calling Trireme") // nolit
		if err := client.SendRequest(request); err != nil {
			err = fmt.Errorf("Policy Server call failed %s", err)
			_ = slog.Alert(err.Error())
			return C.PAM_SESSION_ERR
		}
	}
	return C.PAM_SUCCESS
}

// nolint
//export pam_sm_close_session
func pam_sm_close_session(pamh *C.pam_handle_t, flags, argc int, argv **C.char) C.int {
	slog, _ := syslog.New(syslog.LOG_ALERT|syslog.LOG_AUTH, "mypam")
	slog.Alert("pam_sm_close_session") // nolint
	slog.Close()                       // nolint
	return C.PAM_SUCCESS
}

func findgroupname(gid string) (string, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
	}()
	bs := bufio.NewScanner(f)
	for bs.Scan() {
		line := bs.Text()
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {

			continue

		}
		entry := strings.Split(string(line), ":")
		if len(entry) < 3 {
			continue
		}
		if strings.Compare(entry[2], gid) == 0 {

			return entry[0], nil
		}

	}
	return "", fmt.Errorf("group not found %s", gid)
}

func main() {
}
