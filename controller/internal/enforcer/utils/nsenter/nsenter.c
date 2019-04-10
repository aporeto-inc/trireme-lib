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
#include <fcntl.h>

#define STRBUF_SIZE     128
// Preserved Capabilities
// These capabilities are not reset if they are present in the default set. We don't enable these and will fail
// if they disabled in the process that launches the enforcer. i.e. if they are not in our permitted set 
// -- copy the line as need to disable these capabilities

// ~(1<<CAP_CHOWN)&              --> we need to chown shared folder betwen master and remote
// ~(1<<CAP_DAC_OVERRIDE)&       --> things start failing for logs
// ~(1<<CAP_KILL)&               --> to kill remote enforcer if we cannot clean it normally
// ~(1<<CAP_SYS_PTRACE)&         --> access to /proc to check if we are network namespace
// ~(1<<CAP_NET_ADMIN)&          --> to call setns and iptables programming
// ~(1<<CAP_NET_RAW)&            --> need for raw_socket call used by UDP datapath
// ~(1<<CAP_SYS_RESOURCE)&       --> required set ulimit on number of open files
// ~(1<< CAP_AUDIT_WRITE)&       -->  required by audit functionality
// ~(1<< CAP_AUDIT_CONTROL)&     -->  required by audit functionality

#define MAINCAPMASK				\
  ~(1<<CAP_LEASE)&				\
  ~(1<<CAP_MKNOD)&				\
  ~(1<<CAP_SYS_TTY_CONFIG)&			\
  ~(1<<CAP_SYS_TIME)&				\
  ~(1<<CAP_SYS_NICE)&				\
  ~(1<<CAP_SYS_BOOT)&				\
  ~(1<<CAP_SYS_ADMIN)&				\
  ~(1<<CAP_SYS_TTY_CONFIG)&			\
  ~(1<<CAP_SYS_TIME)&				\
  ~(1<<CAP_SYS_NICE)&				\
  ~(1<<CAP_SYS_BOOT)&				\
  ~(1<<CAP_SYS_PACCT)&				\
  ~(1<<CAP_SYS_MODULE)&				\
  ~(1<<CAP_IPC_OWNER)&				\
  ~(1<<CAP_IPC_LOCK)&				\
  ~(1<<CAP_DAC_READ_SEARCH)&	                \
  ~(1<<CAP_SETGID)&				\
  ~(1<<CAP_SETUID)&				\
  ~(1<<CAP_FOWNER)&				\
  ~(1<<CAP_FOWNER)&				\
  ~(1<<CAP_FSETID)&				\
  ~(1<<CAP_SETPCAP)&				\
  ~(1<<CAP_LINUX_IMMUTABLE)&			\
  ~(1<<CAP_NET_BROADCAST)&			\
  ~(1<<CAP_SYS_RAWIO)&				\
  ~(1<<CAP_SYS_ADMIN)&				\
  ~(1<<CAP_SYS_CHROOT)
  
#define MAINCAPMASK1 ~(1<<(CAP_MAC_OVERRIDE>>5)  


#define REMOTECAPMASK  (			\
  ~(1<<CAP_LEASE)&				\
  ~(1<<CAP_AUDIT_WRITE)&			\
  ~(1<<CAP_AUDIT_CONTROL)&			\
  ~(1<<CAP_MKNOD)&				\
  ~(1<<CAP_SYS_TTY_CONFIG)&			\
  ~(1<<CAP_SYS_TIME)&				\
  ~(1<<CAP_SYS_NICE)&				\
  ~(1<<CAP_SYS_BOOT)&				\
  ~(1<<CAP_SYS_ADMIN)&				\
  ~(1<<CAP_SYS_PACCT)&				\
  ~(1<<CAP_SYS_PTRACE)&				\
  ~(1<<CAP_SYS_CHROOT)&				\
  ~(1<<CAP_SYS_RAWIO)&				\
  ~(1<<CAP_SYS_MODULE)&				\
  ~(1<<CAP_IPC_OWNER)&				\
  ~(1<<CAP_IPC_LOCK)&				\
  ~(1<<CAP_NET_BROADCAST)&			\
  ~(1<<CAP_NET_BIND_SERVICE)&			\
  ~(1<<CAP_LINUX_IMMUTABLE)&			\
  ~(1<<CAP_SETPCAP)&				\
  ~(1<<CAP_SETUID)&				\
  ~(1<<CAP_SETGID)&		                \
  ~(1<<CAP_KILL)&				\
  ~(1<<CAP_FSETID)&				\
  ~(1<<CAP_FOWNER)&		                \
  ~(1<<CAP_DAC_READ_SEARCH)&	                \
  ~(1<<CAP_DAC_OVERRIDE)&	                \
  ~(1<<CAP_NET_BROADCAST)&	                \
  ~(1<<CAP_CHOWN))

static int getuserid(const char *username) {
  struct passwd *entry = NULL;
  entry = getpwnam(username);
  if (entry == NULL){
    return -1;
  }
  return entry->pw_uid;
}

static int getgroupid(const char *groupname) {
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
  cap_user_data_t data = malloc(2*sizeof(struct __user_cap_data_struct));
  char *container_pid_env = getenv("TRIREME_ENV_CONTAINER_PID");
  char *drop_priveleges = getenv("DROP_PRIVELEGES");

  int groupid = getgroupid("aporeto");
  int userid = getuserid("enforcerd");
  int retval = 0;
  if (drop_priveleges != NULL) {
    free(hdr);
    free(data);
    return;
  }
  unsigned int mask=~0;
  if (container_pid_env != NULL){
    //this is remote and we should drop
    mask = REMOTECAPMASK;
  }else {
    mask = MAINCAPMASK;
  }
	  
  
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
  
  data[0].effective = data[0].permitted;
  data[0].inheritable = data[0].permitted;
  err = capset(hdr,data);
  if (err <0) {
    perror("Could Not get cap");
    free(hdr);
    free(data);
    return;
  }

  // drop user only for remotes
  if (container_pid_env != NULL) {
    if (groupid != -1){
      retval = setgid(groupid);
      if (retval < 0) {
	perror("Failed to set group id");
      }
    }
    if (userid != -1) {
      retval = setuid(userid);
      if (retval < 0) {
	perror("Failed to set user id");
      }
    }
  }
  data[0].effective = data[0].permitted&mask;
  if (container_pid_env != NULL) {
    data[0].inheritable = data[0].permitted&REMOTECAPMASK;
  }
  data[0].permitted = data[0].permitted&mask;
  err = capset(hdr,data);
  if (err <0) {
    perror("Could Not set cap");
      free(hdr);
      free(data);
      return;
  }
  
  
  free(hdr);
  free(data);
  return;
  
}

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
    return;
  }
  
  if(netns_path_env == NULL){
    // This means the PID Needs to be used to determine the NetNsPath.
    if(proc_mountpoint == NULL){
      strncpy(mountpoint, "/proc", strlen("/proc")+1);
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
  
  
}




void setupiptables() {
  char *container_pid_env = getenv("TRIREME_ENV_CONTAINER_PID");
  if (container_pid_env == NULL){
    int groupid = getgroupid("aporeto");
    int userid = getuserid("enforcerd");
    if (groupid != -1 && userid != -1) {
        int retval= 0;
	retval = chown("/run/xtables.lock",userid,groupid);
	if (retval <0) {
	  printf("Failed to change ownership of xtables.lock\n")
	}
    }
  }
  return;
}



