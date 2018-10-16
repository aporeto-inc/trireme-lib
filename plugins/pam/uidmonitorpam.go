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

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/monitor/remoteapi/client"
)

// nolint
//export pam_sm_open_session
func pam_sm_open_session(pamh *C.pam_handle_t, flags, argc int, argv **C.char) C.int {
	C.initLog()
	user := C.get_user(pamh)
	service := C.get_service(pamh)
	metadatamap := []string{}
	userstring := "user=" + C.GoString(user)
	metadatamap = append(metadatamap, userstring)

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

		slog.Alert("Calling Trireme") // nolint: errcheck
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
	slog.Alert("pam_sm_close_session") // nolint: errcheck
	slog.Close()                       // nolint: errcheck
	return C.PAM_SUCCESS
}

func main() {
}
