# Trireme and Linux Processes

The goal of Trireme is to assign an identity with every application and use this
identity to transparently insert authentication and authorization in any communication.
The Trireme library has been designed to support both containers as well as any
application supporting linux processes.

In this document we will describe how one can use Trireme with Linux processes
and what are the underlying mechanisms used by the library.

Essentially, Trireme allows you to introduce end-to-end authentication and
authorization between any two Linux processes without ever touching the
process. Through this mechanism you can achieve detailed access control
in your Linux environment without the need for firewall rules, ACLs,
and a complex infrastructure.

# TL;DR - Show me how

In order to illustrate how to use Trireme with Linux processes we will use
the Trireme example with default settings.

1. Download and build trireme-example from https://github.com/aporeto-inc/trireme-example
   Follow the instructions in the Readme file and make sure all the dependencies
   are installed in your system.

2. Start trireme-example in one window
```bash
% sudo trireme-example daemon --hybrid
```
The above command will start the Trireme daemon supporting both Linux Processes
and docker containers and basic PSK authentication. You will be able to see
all the Trireme messages in the window.

3. In a different window start an nginx server protected by Trireme
```bash
% sudo trireme-example run --ports=80 --label=app=web nginx
```
Note, that we use sudo for this since nginx requires root access by default. The
additional parameters are:
- Nginx will be listening on port 80
- The label app=web will be attached to the nginx service.

4. Try to access the nginx server with a standard curl command
```bash
% curl http://127.0.0.1
```
You will see that the curl command fails to connect to the nginx server, even
though the server is running and listening on port 80.

5. Run a curl command with a Trireme identity so that it can actually access
the server:
```bash
% trireme-example run --label=app=web curl -- http://127.0.0.1
```
In this case your curl command will succeed.

6. Let's run now a bash shell in the Trireme context
```bash
% trireme-example run --label=app=web /bin/bash
```
We essentially started just a standard bash shell within the Trireme context
and protected by Trireme. In this case our bash shell can actually access the
nginx server. A simple curl will succeed.
```bash
curl http://127.0.0.1
```

## What did we do?

We started the Trireme daemon and started an nginx server protected by Trireme. By
default only authorized traffic will be able to ever reach this nginx server
at this point. Even processes in the same host will be unable to reach the
server, unless they are also started with Trireme and they are protected by
the same authorization framework.

Trireme allows us very easily to introduce authorization to
any process in the Linux subsystem within the same host or across hosts over
the network.

# Trireme and Linux Processes

In this section we will describe how Trireme introduces the transparent authorization
for every Linux Process. This has several use cases that we will illustrate
in some subsequent blogs. Some examples are:

1. Separate Linux users in different authorization contexts and allow them only
specific access to network resources.
2. Isolate important applications like databases from the network and restrict
access to authorized sources only.
3. Isolate the sshd daemon and allow access only to management tool like
Ansible to ssh into the machine.
4. Restrict communication between processes based on libraries, checksums on
executables, SELinux labels or other structures.

## The forgotten cgroup : net_cls

For several reasons the Linux kernel does not have an easy method to differentiate
traffic based on the source or destination process. However, it has a very
important facility that is not very well documented, but very useful. One
of the cgroup controllers is known as net_cls. When a process is associated with
this controller, the Linux kernel will mark all packets initiated by a process
with a mark that is set in the configuration of the net_cls cgroup. For example,
in a standard Ubuntu distribution you can see the mark in
/sys/fs/cgroup/net_cls/net_cls.classid. The standard value there is 0, indicating
that there is essentially no mark placed on the packets.

In the case of Trireme, you will find a trireme directory under this controller
in /sys/fs/cgroup/net_cls/trireme and Trireme will create a sub-directory there
for every process that is protected by Trireme. Let us assume that the nginx
process above had a process ID of 100. Then Trireme will create the directory
/sys/fs/cgroup/net_cls/trireme/100 and it will populate the net_cls.classid
file there with a mark value. For example 100.

Once Trireme does that, it means that all packets out of the nginx server or any
of its children will be marked with the same mark. We cannot apply the Trireme
ACLs that capture Syn/SynAck traffic only on packets with this mark. As a result,
we can apply policy to a specific Linux processes and not just a container.

Of course we need some more work. Eventually the process will die and we need
to clean up. Fortunately, there is a kernel  facility for that. The file
/sys/fs/cgroup/net_cls/trireme/100/notify_on_release is populated with 1, meaning
that the kernel should notify a release agent that there are no more processes
associated with the particular cgroup. The file /sys/fs/cgroup/net_cls/release_agent
identifies the binary that should be executed when such an event happens.

We can now put all the parts together.
1. The trireme-example command sends an
RPC message to the Trireme daemon requesting to run a process in the Trireme
context.
2. The daemon resolves the policy for the requested command and populates
the right fields in the net_cls file structures.
3. It then does a simple exec and release command to the requested process.
4. When the process dies, the release_agent notifies the Trireme daemon about
the event, and the Trireme daemon cleans up the state.

## Metadata Extractor and Linux Processes

One of the most powerful features of the Trireme approach is the metadata extractor.
In the above example we used a simple method where the labels that are forming
the identity are provided by the user. However, these are not the only attributes
that Trireme identifies and it can be extended to actually associate any attribute
with this identity model.

By default the metadata extractor will capture the following information:
- Md5 checksum of the binary that is executed.
- Library dependencies of the binary
- User ID
- Group ID
- Executable path

The result is that a user can define an authorization policy across any of these
attributes. For example, you can define a policy that only a binary with a specific
checksum can access a database. Or that only a process with a given User ID can
access an application. Or that users with sudo capability can never talk to the
Internet.

One can enhance this metadata extractor with additional sources. For example in
an AWS environment, the ami ID, VPC ID, subnet, SELinux/AppArmor labels and so on.
The possibilities are unlimited.

By associating custom and system metadata with a process, Trireme allows
you to create a "contextual identity" for every Linux process. You can then
use this identity to control access over the network without worrying about IP
addresses and port numbers. It is the identity that matters.
