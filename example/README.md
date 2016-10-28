# Trireme Standalone Implementation

This package provides a simple implementation of network isolation using the
Trireme library in a standalone mode without any control plane. It implements
the trireme policy interface with a simple static policy: Two containers can
talk to each other if they have at least one label that matches.


# Trying it quickly

In order to get a quick proof of concept up and running, you can run the `launch.sh` script or run the following command:

```
docker run \
  --name "Trireme" \
  --privileged \
  --net host \
  -t \
  -v /var/run/docker.sock:/var/run/docker.sock \
aporeto/trireme-example

```

This script will load a docker container in privileged and host mode that will run this example.



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


# Understanding the simple example.

Let's dive into the code. This simple example is almost fully defined in [common.go](common/common.go).
Trireme can be launched with a PresharedKey for authentication (the default mode of this example), or can use a Public Key Infrastructure based on certificates
In both those cases, the configurator package provides helpers that will instantiate Trireme with mostly default parameters.

## Trireme with PSK.

To instantiate Trireme, the following Helper is used:
```
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

```
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
