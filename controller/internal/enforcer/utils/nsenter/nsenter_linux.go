// +build linux

package nsenter

/*

#cgo CFLAGS: -Wall
#include<stdio.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<errno.h>
#include<string.h>
extern int errno;
extern void nsexec();
extern void droppriveleges();
extern void setupiptables();
void __attribute__((constructor)) init(void) {
        //Setup /var/run here this needs to be done here since /var/run will be created at start
        int result = mkdir("/var/run/aporeto",0760);
        if (result < 0) {
           printf("Failed to create directory %s\n",strerror(errno));
        }
	nsexec();
        setupiptables();
        droppriveleges();
}
*/
import "C"
