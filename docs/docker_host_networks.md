# Docker Host Networks and Trireme

Docker and most other container systems have several options for networking.
In most cases, people will choose to use bridge networks or some overlay.
However, for some particular use cases, there is a need for direct access to
a container to the host network. For example, Consul has a use case of
exposing a DNS server using host networks. The RedHat OpenShift router or
several ingress implementations in Kubernetes instantiate the ingress proxy
on a host network so that they can fix its IP address.
(see https://docs.docker.com/engine/userguide/networking/
or
https://docs.openshift.com/enterprise/3.0/install_config/install/deploy_router.html
for some examples).

In general exposing a container directly on the host network poses some
challenges from a security perspective. The container is essentially
attached to the host namespace and can freely interact with any endpoint
with which the host network can communicate. This situation can be
especially dangerous for an ingress proxy that is exposed to the Internet.
Even a non-privileged container with host network access can create a
security vulnerability.

Trireme de-couples security from networking and since it treats containers
and Linux processes as equal, it can give you some additional protections
when your implementation requires access to the host network. Essentially
with Trireme, you can still isolate the container from a networking
perspective, even though it uses the same IP address and ports as your host.

## TL;DR Show me how
To illustrate how to use Trireme with Docker host networks, we will use the
 Trireme example with default settings.
1.	Download and build trireme-example from 
https://github.com/aporeto-inc/trireme-example 
Follow the instructions in the Readme file and make sure all the
dependencies are installed in your system.
2.	Start trireme-example in one window

```bash
% sudo trireme-example daemon --hybrid
```

3.	Start an Nginx container with host network access. In other words, you
Nginx container will be accessible through the host interface without any
network address translations.

```bash
% docker run -l app=nginx --net=host -d nginx
```

If you want to verify that your container is running in host mode, just
issue the command

```bash
% docker inspect <container id> | grep NetworkMode
  "NetworkMode" : "host"
```

4.	Despite the fact that your container is running in host mode, it is
still protected by Trireme and it cannot be actually accessed. The
default policy in Trireme allows two containers or processes to interact
only if they are both protected by Trireme and they have the same labels.
Try:

```bash
% curl http://127.0.0.1
```

This should fail.

5.	Instantiate a curl container now with the same labels as the Nginx
container that we just started.

```bash
% docker run -l app=nginx -it nhoag/curl
```

Assuming that your local docker bridge is at 172.17.0.1 (the default in
docker) the nginx container should be accessible through the bridge IP.
Initiate a curl command to the bridge IP

```bash
root@b84a73c6d5ba:# curl http://172.17.0.1
```

You will see that curl succeeded in this case. You can now exit from the
curl container.

6.	Since Trireme also supports Linux Processes through we can actually
access the container from the host as well, provided that we use Trireme
to control the network capabilities of the Linux process. From your host
cell, just issue the command:

```bash
trireme-example run --label=app=nginx curl -- http://127.0.0.1
```

This command should succeed and you should see the Nginx output. Note, that we start the curl process with the same labels as the Nginx container.

## What Did We Do?

We started a docker container with the net=host parameter. The effect of
this parameter is that the container uses the host network namespace and
has direct access to the interfaces and the network of the host. Doing
that without extra controls poses security risks. Trireme allows you to
protect even containers started in the host network namespace. Since the
container was protected by default by Trireme we instantiated another
container and a Linux process and demonstrated how to use the Trireme
policies to control which network or Linux process can interact with the
host network container.

## Trireme and Host Networking Architecture

As we explained in some of the previous sections, Trireme treats containers
and Linux processes equally from a network security perspective. Trireme
can apply granular policy equally well to a container or a Linux process.

When a container is activated in host network mode, Trireme detects this
activation. Instead of giving full access to the container, it treats it as
a Linux process. It gets the first process (Pid : 1 ) that is run in the
container and places it on a dedicated net_cls cgroup as it would do with
Linux processes. All subsequent processes instantiated/forked inside the
container inherit by default the same policy. It can then apply the
granular policy to the particular container, even though the container is
in the same namespace as the host network. This policy does not affect
any other process or container running on the same host.

This capability makes Trireme very useful in environments that you need
to implement some containers with host network mode.

## Taking it to the extreme
The Trireme isolation for host networks is of course not as strong as a
full network namespace isolation. Containers will still share several
others of the stack. However, in several cases, users are looking for a
less granular isolation, since networking is a pain. See
 (https://medium.com/@copyconstruct/schedulers-kubernetes-and-nomad-b0f2e14a896)
 for some discussion on the topic.

Even the original Borg architecture used this approach to minimize network
complexities. From the corresponding ACM article

"All containers running on a Borg machine share the host’s IP address, so
Borg assigns the containers unique port numbers as part of the scheduling
process."

Although this is not optimal, there are several implementations of docker
in production environments that have decided to take the risk and
instantiate all containers in host network mode since they don't want to
adapt their applications to the concept of either random ports (docker
bridge approach) or IP per container (Kubernetes default). They just did not
want to deal with the complexities of networking. One can not discount
the pragmatic operational reasons that are leading teams down this path.

Obviously, there is an isolation risk with this decision and Trireme can
bridge this gap. By using Trireme as the network policy mechanism, we have
decoupled security from the network. Security is delegated to an end-to-end
authorization function, and the fact that containers live in the same
network namespace does not affect the capability of Trireme to provide
strong isolation.

Therefore, one can use Trireme to implement a container based system
without the need for complex networking. Yes, there are architectural
limitations in some of these choices, but nevertheless it is useful in
some environments.
