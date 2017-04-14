// +build linux !darwin

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#define STRBUF_SIZE     128
void nsexec(void) {

  int fd = 0;
  char path[STRBUF_SIZE];
  char msg[STRBUF_SIZE];
  char * str = getenv("CONTAINER_PID");
  if(str == NULL){
    // We are not running as remote enforcer
    setenv("NSENTER_LOGS", "no container pid", 1);
    return;
  }

  // Setup proc symlink
  snprintf(path, sizeof(path), "/myproc/%s/ns/net", str);

  // Setup FD to symlink
  fd = open(path, O_RDONLY);
  if(fd < 0) {
    snprintf(msg, sizeof(msg), "path:%s fd:%d", path, fd);
    setenv("NSENTER_ERROR_STATE",strerror(-ENOENT), 1);
    setenv("NSENTER_LOGS", path, 1);
    return;
  }

  // Set namespace
  int retval = setns(fd,0);
  snprintf(msg, sizeof(msg), "path:%s fd:%d retval:%d", path, fd, retval);
  setenv("NSENTER_LOGS",msg,1);
  if(retval < 0){
    setenv("NSENTER_ERROR_STATE",strerror(errno),1);
  }
}
