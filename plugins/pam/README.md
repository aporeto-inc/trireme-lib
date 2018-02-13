# PAM Authorization Module for Trireme 

The PAM Authorization module allws the integration of Trireme with PAM Linux module. On every authorization
request to the PAM module, the plugin can intercept the login or sudo attempt and activate the user 
in a specific network context where access to network resources is managed through the Trireme 
end-to-end authorization process. A simple use case is to give specific network access to specific 
users such as the case of a jump-box in a cloud environment. 

To build the module simple do:

```bash 
go build -buildmode=c-shared -o pam-module.so
```

This file needs to be copied to the directory of PAM modules (usually in /lib/x86_64-linux-gnu/security/). Once 
installed there, you can configure the PAM module to invoke the plugin by adding the corresponding
directive. For example, you can add this line to /etc/pam.d/sudo 

```
session required pam_aporeto_uidm.so in 
```

Once this is installed, running sudo -u <anyuser> /bin/bash will cause the PAM module to send an event
to Trireme and a unique network context will be activated for this user. Based on the user
information one can select the right network policy to apply to the user.

You can achieve the same thing for the login shell by adding the directive to the 
/etc/pam.d/login file. 
