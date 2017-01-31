# Trireme Standalone Implementation

This package provides a simple implementation of network isolation using the
Trireme library in a standalone mode without any control plane. It implements
the trireme policy interface with a simple static policy: Two containers can
talk to each other if they have at least one label that matches.


# Trying it quickly

In order to get a quick proof of concept up and running, you can run the `launch.sh` script or run the following command:

```bash
docker run \
  --name "Trireme" \
  --privileged \
  --net host \
  --pid host \
  -t \
  -v /var/run:/var/run \
aporeto/trireme-example

```

This script will load a docker container in privileged and host mode that will run this example. Trireme
will be installed with remote enforcers and it is compatible with any networking technique that is
possible in the host machine.

You can start a docker container with a specific label (in this case **app=web**)

```bash
docker run -l app=web -d nginx
```

A client will only be able to open a request to this container if it also has the same label ( **app=web** ). For example:

```bash
docker run -l app=web -it centos
curl http://<nginx-IP>
```
will succeed.

A client that starts with different label (for example **app=database**) will fail to connect:

```bash
docker run -l app=database -it centos
curl http://<nginx-IP>
```
fails.

## Trying it with Docker Swarm

Trireme also has support for Docker Swarm including any overlay networks. This functionality is
based on a remote execution capability where Trireme will intercept traffic before any
of the libnetwork plugins even see the packets. This allows Trireme to support any of the
network plugins.

In order to try it, compile the example:

```bash
make build
```

This will output Trireme in the local directory. If you want to install it in a system
path try
```bash
make install
```

By default this installs trireme in /usr/local/bin. If you want to change the destination please
edit the Makefile and the BIN_PATH variable.


```bash
sudo ./trireme --remote --swarm
```

This activates Trireme with the remove enforcer capabilities and a Swarm specific
metadata extractor that will interpret metadata from Docker Swarm.

In your swarm cluster you can create an overlay network
```bash
docker network create --driver overlay mynet
```

Then you can create a two services:
```bash
docker service create  --network mynet --name web1 -l app=web nginx
docker service create --network mynet --name client -l app=web tester
```

Assuming that your tester container includes some curl capability, you can immediately
see that the tester can access the nginx server.

## Trying Trireme with any Linux process

Trireme supports any Linux process by extracting metadata from the Linux environment as
well as attributes supplied by the users. Trireme uses network cgroups (net_cls) capabilities
to isolate traffic from each process.

First, compile the Trireme example as in the previous section. Start Trireme in hybrid mode
supporting both Linux processes and containers at the same time. You must specify the networks
that you want Trireme to apply (by default it uses the docker bridge only). In the example
below we apply Trireme only on the localhost traffic.

```bash
sudo ./trireme daemon --hybrid --target-networks=127.0.0.1
```

Start an nginx server as a Linux process (make sure you have the nginx binary available at `/usr/sbin/nginx`, or adapt accordingly) :

```bash
sudo ./trireme run --ports=80 --label=app=web /usr/sbin/nginx  -- '-g daemon off;'
```

The above command starts the nginx server, listening on port 80. If you try to access this nginx
server with a curl command communication will fail. Now start with a curl command and associated
metadata:

```bash
./trireme run --label=app=web /usr/bin/curl -- -p http://172.17.0.1
```
This command should succeed.

You can also start a docker container with the same metadata
```bash
docker run -l app=web -it centos
```

And you can access the nginx server at the host. However if you start the container
with different labels you will not able able to access the nginx container.

# Understanding the simple example.

Let's dive into the code. This simple example is almost fully defined in [common.go](common/common.go).
Trireme can be launched with a PresharedKey for authentication (the default mode of this example), or can use a Public Key Infrastructure based on certificates
In both those cases, the configurator package provides helpers that will instantiate Trireme with mostly default parameters.

## Trireme with PSK.

To instantiate Trireme, the following Helper is used:
```go
configurator.NewPSKTriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, syncAtStart, key)
```
The parameters are the following:
* `serverID` is a unique reference/name for the node where the instance of Trireme is running.
* `networks` is an array of CIDR networks that packets with those destinations are policed. In most of cases, giving the whole IP Space is a good default.
* `resolver` is a pointer to the PolicyResolver that implements the `trireme.PolicyResolver` interface. In this example this is the `CustomPolicyResolver` struct.
* `processor` is an optional reference
* `eventCollector` is an optional reference to a logger that collects all kind of events around your containers.
* `syncAtStart` is a bool that defines if the existing DockerContainers will have a policy applied at start time. In most of the cases, you want this to be enabled. In the example, we left it to false so that Docker containers running prior to Trireme coming up will be left untouched.
* `key` is an array of bytes that represent a PresharedKey.

The configurator returns a reference to Trireme and to the Monitor. Both of those references need to be explicitely started (with Start()) in order to start processing events.

## Trireme With PKI

For more complex use cases, Trireme can be used with a Private Key Infrastructure. In this case, each node will have a Private Key and associated Public Key cert signed by a recognized CA.

The configurator helper is similar to the PresharedKey one, except that it takes into input the PKI information:

```go
configurator.NewPKITriremeWithDockerMonitor(serverID, networks, resolver, processor, eventCollector, syncAtStart, keyPEM, certPEM, caCertPEM)
```

* `KeyPEM` is the Private Key in the PEM format.
* `CertPEM` is the Certificate for the current node. Must certify the ServerID name given as parameter
* `caCertPEM` is the CA that is used to validate all the Certificates of foreign nodes.

The implementation also provides a simple script for generating the necessary
certificates.


```bash
./create_certs.sh
```

# Building

If you want to build the binary without a docker container, you must have 'libnetfilter-queue' installed in your system. For example in an Ubuntu distribution:

```bash
sudo apt-get update
sudo apt-get install -y libnetfilter-queue-dev iptables
```

for Centos:
```bash
sudo yum update
sudo yum install libnetfilter_queue-devel
```

Building is just:

```bash
# Install the required dependencies
glide install
# Build
make build
```
