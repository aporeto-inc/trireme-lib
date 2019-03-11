// +build linux

package nsenter

/*

#cgo CFLAGS: -Wall
#include<stdio.h>

extern void nsexec();
extern void droppriveleges();
extern void setupiptables();
void __attribute__((constructor)) init(void) {
	nsexec();
        setupiptables();
        droppriveleges();
}
*/
import "C"
