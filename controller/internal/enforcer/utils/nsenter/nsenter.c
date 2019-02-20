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
#include <unistd.h>
#include<sys/capability.h>
#include<sys/prctl.h>
#include <pwd.h>
#include <grp.h>

#define STRBUF_SIZE     128
void droppriveleges();
void nsexec(void) {

  int fd = 0;
  char path[STRBUF_SIZE];
  char msg[STRBUF_SIZE];
  char mountpoint[STRBUF_SIZE] = {0};
  char *container_pid_env = getenv("TRIREME_ENV_CONTAINER_PID");
  char *netns_path_env = getenv("TRIREME_ENV_NS_PATH");
  char *proc_mountpoint = getenv("TRIREME_ENV_PROC_MOUNTPOINT");
  if(container_pid_env == NULL){
    // We are not running as remote enforcer
    setenv("TRIREME_ENV_NSENTER_LOGS", "no container pid", 1);
    droppriveleges();
    return;
  }
  if(netns_path_env == NULL){
    // This means the PID Needs to be used to determine the NetNsPath.
    if(proc_mountpoint == NULL){
      strncpy(mountpoint, "/proc", strlen("/proc"));
    }else{
      strncpy(mountpoint, proc_mountpoint, STRBUF_SIZE);
    }
    // Setup proc symlink
    snprintf(path, sizeof(path), "%s/%s/ns/net", mountpoint, container_pid_env);
  } else {
    // We use the env variable as the Path.
    strncpy(path, netns_path_env, STRBUF_SIZE);
  }

  // Setup FD to symlink
  fd = open(path, O_RDONLY);
  if(fd < 0) {
    snprintf(msg, sizeof(msg), "path:%s fd:%d", path, fd);
    setenv("TRIREME_ENV_NSENTER_ERROR_STATE",strerror(-ENOENT), 1);
    setenv("TRIREME_ENV_NSENTER_LOGS", path, 1);
    return;
  }

  // Set namespace
  int retval = syscall(308,fd,0);
  snprintf(msg, sizeof(msg), "path:%s fd:%d retval:%d", path, fd, retval);
  setenv("TRIREME_ENV_NSENTER_LOGS",msg,1);
  if(retval < 0){
    setenv("APORET_ENV_NSENTER_ERROR_STATE",strerror(errno),1);
  }
 
  // adjust
  droppriveleges();
  
  
}

int getuserid(const char *username) {
  struct passwd *entry = NULL;
  entry = getpwnam(username);
  if (entry == NULL){
    return -1;
  }
  return entry->pw_uid;
}


int getgroupid(const char *groupname) {
  struct group *grp = NULL;
  grp = getgrnam(groupname);
  if (grp==NULL) {
    return -1;
  }
  return grp->gr_gid;
}


// droppriveleges called in init due to the same reason we do setns here. setuid setgid are per thread calls
void droppriveleges() {
  cap_user_header_t hdr = malloc(sizeof(struct __user_cap_header_struct));
  cap_user_data_t data = malloc(sizeof(struct __user_cap_data_struct));
  const char *path = "/tmp/netns";
  int fd =0;
  int n =0;
  int w = 0;
  char buf[100] = {'0'};
  prctl(PR_SET_KEEPCAPS ,1,0,0,0); // nolint
  hdr->pid = getpid();
  hdr->version = 0x20080522;
  int err = capget(hdr,data);
  if (err <0) {
    perror("Could Not get cap");
    free(hdr);
    free(data);
    return;
  }
  if (fd <= 0){
      fd = open(path,O_CREAT|O_WRONLY|O_APPEND,0);
    }
  n = snprintf(buf,100,"before capset setgid permitted=%x effective=%x inher=%x\n",data[0].permitted,data[0].effective,data[0].inheritable);
  w = write(fd,buf,n);
  if (w<0) {
    printf("Failed to write to file\n");
  }

  data[0].effective = data[0].permitted;
  data[0].inheritable = data[0].permitted;
  err = capset(hdr,data);
  if (err <0) {
    perror("Could Not get cap");
    free(hdr);
    free(data);
    return;
  }

  hdr->pid = getpid();
  hdr->version = 0x20080522;
  err = capget(hdr,data);
  if (err <0) {
    perror("Could Not get cap");
    free(hdr);
    free(data);
    return;
  }
  
  if (fd <= 0){
      fd = open(path,O_CREAT|O_WRONLY|O_APPEND,0);
  }
  n = snprintf(buf,100,"after capset  permitted=%x effective=%x inher=%x \n",data[0].permitted,data[0].effective,data[0].inheritable);
  w = write(fd,buf,n);
  if (w<0) {
    printf("Failed to write to file\n");
  }
  int groupid = getgroupid("aporeto");
  int retval = 0;
  if (groupid == -1){
   retval = setgid(65534);
  }else{
    retval = setgid(groupid);
  }
  
  
  if (retval < 0) {
    if (fd <= 0){
      fd = open(path,O_CREAT|O_WRONLY|O_APPEND,0);
    }
    n = snprintf(buf,100,"setgid %s\n",strerror(errno));
    w=  write(fd,buf,n);
    
  }

  int userid = getuserid("enforcerd");
  if (userid == -1) {
    retval = setuid(65534);
  }else{
    retval = setuid(userid);
  }
  if (retval< 0){
    if (fd <=0){
    fd = open(path,O_CREAT|O_WRONLY|O_APPEND,0);
    }
    n = snprintf(buf,100,"setuid %s\n",strerror(errno));
    w = write(fd,buf,n);
    
    
  }
  data[0].effective = data[0].permitted;
  data[0].inheritable = data[0].permitted;
  err = capset(hdr,data);
  if (err <0) {
    perror("Could Not get cap");
    free(hdr);
    free(data);
    return;
  }
  err = capget(hdr,data);
  if (err <0) {
    perror("Could Not get cap");
  }
  if (fd <=0) {
    fd = open(path,O_CREAT|O_WRONLY|O_APPEND,0);
  }
  n = snprintf(buf,100,"After setgid effective=%x permitted=%x inheritables=%x\n",data[0].effective,data[0].permitted,data[0].inheritable);
   w = write(fd,buf,n);
  close(fd);
  free(hdr);
   free(data);
   return;
  
}



