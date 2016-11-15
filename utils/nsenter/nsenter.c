#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<errno.h>
void nsexec(void){
  char *path = NULL;
  char *str = getenv("Container_PID");
  int fd =0;
  int path_len = strlen("/proc/") + strlen(str) + strlen("/ns/net");
  path = calloc(1,path_len+1);
  snprintf(path,path_len,"/proc/%s/ns/net",str);
  fd = open(path,O_RDWR);
  int retval = setns(fd,0);
  if(retval < 0){
    setenv("NSENTER_ERROR_STATE",strerror(errno),1);
  }else{
    setenv("NSENTER_ERROR_STATE"," ",1);
  }
  
}


