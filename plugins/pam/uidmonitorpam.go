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
	"fmt"
	"log/syslog"
	"os"
	"os/user"

	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/monitor/remoteapi/client"
)

func getGroupList(username string) ([]string, error) {
	slog, _ := syslog.New(syslog.LOG_ALERT|syslog.LOG_AUTH, "mypam")
	defer func() {
		_ = slog.Close()
	}()
	userhdl, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	gids, err := userhdl.GroupIds()
	if err != nil {
		return nil, err
	}
	groups := make([]string, len(gids))
	index := 0
	for _, gid := range gids {
		grphdl, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}
		groups[index] = "groupname=" + grphdl.Name
		index++

	}
	return groups[:index], nil
}

// nolint
//export pam_sm_open_session
func pam_sm_open_session(pamh *C.pam_handle_t, flags, argc int, argv **C.char) C.int {
	C.initLog()
	user := C.get_user(pamh)
	service := C.get_service(pamh)
	metadatamap := []string{}
	userstring := "user=" + C.GoString(user)
	metadatamap = append(metadatamap, userstring)
	if groups, err := getGroupList(C.GoString(user)); err == nil {
		metadatamap = append(metadatamap, groups...)
	}

	if service != nil {
		metadatamap = append(metadatamap, "SessionType="+C.GoString(service))
	} else {
		metadatamap = append(metadatamap, "SessionType=login")
	}

	request := &common.EventInfo{
		PUType:    common.UIDLoginPU,
		PUID:      C.GoString(user),
		Name:      "login-" + C.GoString(user),
		PID:       int32(os.Getpid()),
		Tags:      metadatamap,
		EventType: "start",
	}

	if C.is_root(user) == 1 {
		//Do nothing this is login shell account
	} else {
		//Do something
		slog, _ := syslog.New(syslog.LOG_ALERT|syslog.LOG_AUTH, "mypam")
		defer func() {
			_ = slog.Close()
		}()

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

func main() {
}
