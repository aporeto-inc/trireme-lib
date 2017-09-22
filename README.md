# Trireme

<img src="https://www.aporeto.com/wp-content/uploads/2016/10/trireme-logo-final-b.png" width="400">

[![Build Status](https://travis-ci.org/aporeto-inc/trireme.svg?branch=master)](https://travis-ci.org/aporeto-inc/trireme) [![Code Coverage](https://codecov.io/gh/aporeto-inc/trireme/branch/master/graph/badge.svg)](https://codecov.io/gh/aporeto-inc/trireme) [![Twitter URL](https://img.shields.io/badge/twitter-follow-blue.svg)](https://twitter.com/aporeto_trireme) [![Slack URL](https://img.shields.io/badge/slack-join-green.svg)](https://triremehq.slack.com/messages/general/) [![License](https://img.shields.io/badge/license-GPL--2.0-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html) [![Documentation](https://img.shields.io/badge/docs-godoc-blue.svg)](https://godoc.org/github.com/aporeto-inc/trireme)


Welcome to Trireme, an open-source library curated by Aporeto to provide segmentation for cloud-native applications.  Trireme is a Zero-Trust networking library that makes it possible to setup security policies and segment applications by enforcing end-to-end authentication and authorization and without the need for complex control planes or IP/port-centric ACLs and east-west firewalls.

Trireme supports both containers and Linux Processes and allows security policy enforcement between any of these entities.

# TL;DR

You can try out Trireme quickly via one of these methods:

* [Trireme as a Docker container](https://github.com/aporeto-inc/trireme-example)
* [Trireme as a Kubernetes daemonset](https://github.com/aporeto-inc/trireme-kubernetes/tree/master/deployment)
* [Trireme as a Kubernetes daemonset in Red Hat OpenShift](https://github.com/aporeto-inc/trireme-kubernetes/tree/master/deployment/OpenShift)

# Description

In the Trireme world, a processing unit end-point can be a container, Kubernetes POD, or a general Linux process. We will be referring to processing units as PUs throughout this discussion.


The technology behind Trireme is streamlined, elegant, and simple. It is based on The concepts of Zero-Trust networking:


1. The identity is the set of attributes and metadata that describes the container as key/value pairs. Trireme provides an extensible interface for defining these identities. Users can choose customized methods appropriate to their environment for establishing PU identity. For example, in a Kubernetes environment, the identity can be the set of labels identifying a POD.
2. There is an authorization policy that defines when containers with different types of identity attributes can interact or exchange traffic. The authorization policy implements an Attribute-Based Access Control (ABAC) mechanism (https://en.wikipedia.org/wiki/Attribute-Based_Access_Control), where the policy describes relationships between identity attributes.
3. Every communication between two processes or containers is controlled through a cryptographic end-to-end authentication and authorization step, by overlaying an authorization function over the TCP negotiation. The authorization steps are performed during the `SYN`/`SYNACK`/`ACK` negotiation.


The result of this approach is the decoupling of application segmentation from the underlying network IP addresses because this approach is centered on workload identity attributes and interactions between workloads. Application segmentation can be achieved simply by managing application identity and authorization policy. Segmentation granularity can be adjusted based on the needs of the platform.


Trireme is a node-centric library.  Each node participating in the Trireme cluster must spawn one instance of a process that uses this library to transparently insert the authentication and authorization step. Trireme provides the data path functions but does not implement either the identity management or the policy resolution function. Function implementation depends on the particular operational environment. Users have to provide PolicyLogic (ABAC “rules”) to Trireme for well-defined PUs, such as containers.

# Existing implementation using Trireme library

* [This example ](https://github.com/aporeto-inc/trireme-example) is a straightforward implementation of the PolicyLogic for a simple use-case.

* [Kubernetes-Integration ] (https://github.com/aporeto-inc/kubernetes-integration) is a full implementation of PolicyLogic that follows the Kubernetes Network Policies model.

* [Bare-Metal-Integration] (https://github.com/aporeto-inc/trireme-bare-metal) is an implementation of Trireme for Kubernetes on-Prem, with a Cumulus agent that allows you to have a very simple networking model (routes are advertised by Cumulus) together with Trireme for policy enforcement.


# Security Model

Trireme is a Zero-Trust networking library. The security model behind Zero-trust networking is:
* The Network is always untrusted. It doesn't matter if you are inside or outside your enterprise.
* Every Flow/Connection needs to be authenticated and authorized by the endpoints
* The network information (IP/Port) is completely irrelevant to the authorization/authentication.

With Trireme, there is no need to define any security rules with IPs, port numbers, or ACLs.   Everything is based on identity attributes; your IP and port allocation scheme is not relevant to Trireme and it is compatible with most underlying networking technologies. The end-to-end authentication and authorization approach is also compatible with NATs and IPv4/IPv6 translations.


A PU is a logical unit of control to which you attach identity and authorization policies. It provides a simple mechanism where the identity is derived out of the Docker manifest; however, other mechanisms are possible for more sophisticated identity definition.   For instance, you may want to tag your 3-tier container application as "frontend," "backend," and "database." By associating corresponding labels and containers, these labels become "the identity." A policy for the “backend” containers can simply accept traffic only from “frontend” containers. Alternatively, an orchestration system might define a composite identity for each container and implement more sophisticated policies.


PolicyLogic defines the set of authorization rules as a function of the identity of attributes and loads these rules into Trireme when a container is instantiated. Authorization rules describe the set of identities with which a particular container is allowed to interact. We provide an example of this integration logic with Kubernetes  [here](https://github.com/aporeto-inc/kubernetes-integration). Furthermore, we provide an example of a simple policy where two containers can only talk to each other if they have matching labels in [this example](https://github.com/aporeto-inc/trireme/tree/master/example). Each rule defines a match based on the identity attributes. PolicyLogic assumes a whitelist model where everything is dropped unless explicitly allowed by the authorization policy.


PU identities are cryptographically signed with a node specific secret and sent as part of a TCP connection setup negotiation. Trireme supports both mutual and receiver-only authorization. Moreover, it supports two authentication and signing modes: (1) A pre-shared key and (2) a PKI mechanism based on ECDSA. In the case of ECDSA, public keys are either transmitted on the wire or pre-populated through an out-of-band mechanism to improve efficiency. Trireme also supports two identity encoding mechanisms: (1) A signed JSON Web Token (JWT) and (2) a custom binary mapping mechanism.


With these mechanisms, the Trireme run-time on each node will only allow communication after an end-to-end authentication and authorization step is performed between the containers.


# Trireme Architecture


Trireme is built as a set of modules (Go packages) that provide a default implementation for each component.  It is simple to swap the default implementation of each of those modules with custom-built ones for more complex and specific features.

Conceptually, Trireme acts on PU events. In the default implementation, the PU is a Docker container.  Trireme can be extended easily to other PUs such as processes, files, sockets, and so forth.

![Trireme Architecture](https://www.aporeto.com/wp-content/uploads/2016/10/trireme.png)

* `Trireme` is the central package providing policy instantiation logic. It receives PU events from the `Monitor` and dispatches the resulting generated policy to the other modules.
* The `Monitor` listens to a well-defined PU creation module.  The built-in monitor listens to Docker events and generates a standard Trireme Processing Unit runtime representation. The `Monitor` hands-over the Processing Unit runtime to `Trireme`.
* The `PolicyResolver` is implemented outside of Trireme. `Trireme` calls the `PolicyResolver` to get a PU policy based on a PU runtime. The `PolicyResolver` depends on the orchestration system used for managing identity and policy. If you plan to implement your own Policy with Trireme, you will essentially need to implement a `PolicyResolver`
* The `Supervisor` implements the policy by redirecting the TCP negotiation packets to user space. The default implementation uses IPTables with LibNetfilter.
* The `Enforcer` enforces the policy by analyzing the redirected packets and enforcing the identity and policy rules that are defined by the `PolicyResolver` in the PU policy. Trireme supports to day a `Remote ` and a `local` enforcer. The `Remote` enforcer is advised as it is remotely started into the network namespace of the  Processing Unit, therefore not interfering at all with existing Networking implementation on the default/host namespace.


# Defining Your Own Policy

Trireme allows you to define any type of identity attributes and policies to associate with PUs.
In order to define your own policies and identities, you need to implement a PolicyResolver interface that will receive policy requests from Trireme whenever a policy resolution is required.

# PolicyResolver Implementation

A couple of Helpers are provided as part of the `configurator` packages that loads all of Trireme’s modules with the most common settings:

* `NewPSKTriremeWithDockerMonitor` loads Trireme with the default Docker Monitor. A PreSharedKey is used for remote node signature verification.


* `NewPKITriremeWithDockerMonitor` loads Trireme with the default Docker Monitor. ECDSA is used for signatures. In this case, a publicKeyAdder interface is returned. This interface is used to populate the certificates of the remote nodes.


In parameter to the helper of your choice, you need to give your own `PolicyResolver` interface implementation:

```go
type PolicyResolver interface {

	// ResolvePolicy returns the policy.PUPolicy associated with the given contextID using the given policy.RuntimeReader.
	ResolvePolicy(contextID string, RuntimeReader policy.RuntimeReader) (*policy.PUPolicy, error)

	// HandleDeletePU is called when a PU is stopped/killed.
	HandlePUEvent(contextID string, eventType monitor.Event)
}
```

Each Container event generates a call to `HandlePUEvent`

The `PolicyResolver` can then issue explicit calls to the `PolicyUpdater` in order to push a policyUpdate for an already running ProcessingUnit:

```go
type PolicyUpdater interface {

    // UpdatePolicy updates the policy of the isolator for a container.
    UpdatePolicy(contextID string, newPolicy *policy.PUPolicy) <-chan error
}
```

# Prerequisites

* Trireme requires IPTables with access to the `Mangle` module.
* Trireme requires access to the Docker event API socket (`/var/run/docker.sock` by default)
* Trireme requires privileged access.
* Trireme requires to run in the Host PID namespace.

# License

The Trireme package, although written in Go currently uses the libnetfilter-queue library:
http://www.netfilter.org/projects/libnetfilter_queue/

This library provides the API to the Linux Kernel for interfacing with the NFQUEUE module
that transfers packets to user space for processing. Since this library is provided
under the GPL v2 license, and is linked with the rest of the Trireme code through CGO
we are also releasing this code with a GPL v2 license.

We are taking this step to protect any users of the library from an accidental violation
of the GPL guidelines.

[![Analytics](https://ga-beacon.appspot.com/UA-90317101-1/welcome-page)](https://github.com/igrigorik/ga-beacon)
