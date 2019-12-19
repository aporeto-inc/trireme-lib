package main

/*
#cgo LDFLAGS: -lpam -fPIC
#include <errno.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include<syslog.h>
int get_uid(char *user);

// get_user pulls the username out of the pam handle.
char *get_user(pam_handle_t *pamh) {
  if (!pamh)
    return NULL;
  int pam_err = 0;
  const char *user;

  if ((pam_err = pam_get_item(pamh, PAM_USER, (const void**)&user)) != PAM_SUCCESS)
    return NULL;

  return strdup(user);
}

// get_user pulls the username out of the pam handle.
char *get_ruser(pam_handle_t *pamh) {
  if (!pamh)
    return NULL;
  int pam_err = 0;
  const char *user;
  if ((pam_err = pam_get_item(pamh, PAM_RUSER, (const void**)&user)) != PAM_SUCCESS)
    return NULL;
  return strdup(user);
}



char *get_service(pam_handle_t *pamh){
  int pam_err = 0;
  if (!pamh)
    return NULL;
  const char *service;
  if ((pam_err = pam_get_item(pamh, PAM_SERVICE, (const void**)&service)) != PAM_SUCCESS)
    return NULL;
  return strdup(service);
}

void initLog() {
   openlog(NULL,LOG_PID,LOG_AUTH);
}

int is_system_user(char *user){
   struct passwd entry;
   struct passwd *result;
   char *buf;
   size_t bufsize;
  int s;
  bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize == -1)
        bufsize = 16384;
   buf = malloc(bufsize);
   s = getpwnam_r(user,&entry,buf,bufsize,&result);
   if(result == NULL){
     if (s ==0){
       return 0;
     }
   }
//We are late enough in the stack to get no errors about missing users ideally

if(strcmp("/bin/nologin",entry.pw_shell)== 0 || strcmp("/bin/false",entry.pw_shell) || strlen(entry.pw_shell) < 1){
    syslog(LOG_ALERT,"Called with ruser %s",entry.pw_shell);
    syslog(LOG_ALERT,"Called with ruser %s",entry.pw_passwd);
    return 1;
 }
if(entry.pw_passwd[0] == '!' || entry.pw_passwd[0] == '*' || strcmp(entry.pw_passwd,"x") == 0){
return 1;
}
  return 0;
}

int is_root(char *user){
  struct passwd entry;
  struct passwd *result;
  char *buf;
  size_t bufsize;
  int s;
  int i =0;

  bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize == -1)
        bufsize = 16384;
   buf = malloc(bufsize);
   s = getpwnam_r(user,&entry,buf,bufsize,&result);
   if(result == NULL){
     if (s ==0){
       return 0;
     }
   }
   if (entry.pw_uid == 0){
      return 1;
   }

  return 0;
}
*/
import "C"
