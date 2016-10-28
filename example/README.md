# Trireme Standalone Implementation

This package provides a simple implementation of network isolation using the
Trireme library in a standalone mode without any control plane. It implements
the trireme policy interface with a simple static policy: Two containers can
talk to each other if they have at least one label that matches.


# Trying it quickly

In order to get a quick proof of concept up and running, you can run the `launch.sh` script.
This script will load a docker container in privileged and host mode that will run this example.



You can start a docker container using the standard commands

```bash
docker run -l app=web -d nginx
```

A client will only be able to talk to this container if it also has the same label. For example:

```bash
docker run -l app=web -it centos
curl http://<nginx-IP>
```
will succeed.

A client that starts with different labels will fail to connect:

```bash
docker run -l app=database -it centos
curl http://<nginx-IP>
```


# Understanding the simple example.

## Trireme with PSK.

## Trireme With PKI

The implementation also provides a simple script for generating the necessary
certificates.

In order to use, first create some certificates

```bash
./create_certs.sh
```


Then run the standalone implementation

```bash
go build -o standalone
sudo ./standalone
```
