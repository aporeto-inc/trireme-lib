# Trireme

<img src="https://www.aporeto.com/wp-content/uploads/2016/10/trireme-logo-final-b.png" width="400">

Welcome to Trireme, an open-source library curated by Aporeto to provide segmentation for cloud-native applications.  Trireme makes it possible to setup security policies and segment applications by enforcing end-to-end authentication and authorization and without the need for complex control planes or IP/Port-centric ACLs and east-west firewalls.


In the Trireme world, an end-point can be a container, Kubernetes POD, or in general any Linux process and will be referred as Processing Unit (PU) in this discussion.


The technology behind Trireme is actually very simple:


1. Every PU gets an identity description. The identity is the set of attributes/metadata that can describe the container as key/value pairs and Trireme provides an extensible interface for defining such an identity. Users can choose methods custom to their environment for defining PU identity. For example in a Kubernetes environment, the identity can be the set of labels identifying a POD.
2. An authorization policy that defines when containers with different types of identity attributes can interact or exchange traffic. The authorization policy essentially implements an Attribute Based Access Control (ABAC) mechanism (https://en.wikipedia.org/wiki/Attribute-Based_Access_Control) , where the policy describes relationships between identity attributes. (for an intro to ABAC see the NIST Video https://www.youtube.com/watch?v=cgTa7YnGfHA)
3. Every communication between two processes or containers is controlled through a cryptographic end-to-end authentication and authorization step, by overlaying an authorization function over the TCP negotiation. The authorization steps are performed during the `SYN`/`SYNACK`/`ACK` negotiation.


The result of this approach is that application segmentation is completely decoupled from the underlying network IP addresses and it is centered around workload identity attributes and interactions between workloads. Application segmentation can be simply achieved by managing application identity and authorization policy and the granularity of the segmentation can be refined based on the needs of the platform.


Trireme is a node-centric library.  Each node participating in the Trireme cluster must spawn one instance of a process that uses this library to transparently insert the authentication and authorization step. Trireme provides the data path functions, but does not implement either the identity management or the policy resolution functions. This depends on the specific operational environment. Users of the have to provide the PolicyLogic (ABAC “rules”) to Trireme for well-defined Processing Units (PUs), such as containers.  


[This example ](https://github.com/aporeto-inc/trireme/tree/master/example) is a good and straightforward implementation of the PolicyLogic for a simple use-case.

[Kubernetes-Integration ] (https://github.com/aporeto-inc/kubernetes-integration) is a full implementation of PolicyLogic that follows the Kubernetes Network Policies model.

# Security Model


With Trireme, there is no need to define any security rules with IPs, port numbers or ACLs.   Everything is based on identity attributes; your IP and port allocation scheme is not relevant to Trireme and it is compatible with most underlying networking technologies. The end-to-end authentication and authorization approach is also compatible with NATs and IPv4/IPv6 translations.


A Processing Unit (PU) is a logical unit of control to which you attach identity and authorization policies.  It provides a simple mechanism where the identity is derived out of the Docker manifest, but other mechanisms are possible for more sophisticated identity definition.   For instance, you may want to tag your 3-tier container application as "frontend," "backend," and "database", by associating the corresponding  labels with the containers and these labels become the identity. A policy for the “backend” containers is simply to accept traffic only from the “frontend” containers. Alternatively, an orchestration system might define a composite identity for each container and more sophisticated policies.


The Policy Logic defines the set of authorization rules as a function of the identity of attributes and loads these rules into Trireme when a container is instantiated. The authorization rules describe the set of identities that the particular container is allowed to interact with. We provide an example of this integration logic with Kubernetes in [link] and an example of simplistic policy where two containers can only talk to each other if they have the same labels in [link]. Each rule defines a match based on the identity attributes and it assumes a white-list model where everything is dropped unless explicitly allowed by the authorization policy.


PU identities are cryptographically signed with a node specific secret and sent as part of a TCP connection setup negotiation. Trireme supports both mutual authorization or receiver only authorization and supports two authentication and signing modes:  a pre-shared key mechanism and a PKI mechanism based on ECDSA. In the case of ECDSA, public keys are either transmitted on the wire or pre-populated through an out-of-band mechanism to improve efficiency. Trireme supports two identity encoding mechanisms:  either as a signed JSON Web Token (JWT) or through a custom binary mapping mechanism.


With these mechanisms, the Trireme agent on each node will only allow communication after an end-to-end authentication and authorization step is performed between the containers.


# Trireme Architecture


Trireme is built as a set of modules (Go packages) that provides a default implementation for each component.  It is simple to swap the default implementation of each of those modules with custom-built ones for more complex and specific features.

Conceptually, Trireme acts on PU events. In the default implementation, the PU is a Docker container.  Trireme can be extended easily to other PUs such as processes, files, sockets, and so forth.

![Trireme Architecture](/architecture.png)

* `Trireme` is the central package providing policy instantiation logic. It receives PU events from the `Monitor` and dispatches the resulting generated policy to the other modules.
* The `Monitor` listens to a well-defined PU creation module.  The built-in monitor listens to Docker events and generates a standard Trireme Processing Unit runtime representation. The `Monitor` hands-over the Processing Unit runtime to `Trireme`.
* The `PolicyResolver` is implemented outside of Trireme. `Trireme` calls the `PolicyResolver` to get a PU policy based on a PU runtime. The `PolicyResolver` depends on the orchestration system used for managing identity and policy. If you plan to implement your own Policy with Trireme, you will essentially need to implement a `PolicyResolver`
* The `Supervisor` implements the policy by redirecting the TCP negotiation packets to user space. The default implementation uses IPTables with LibNetfilter.
* The `Enforcer` enforces the policy by analyzing the redirected packets and enforcing the identity and policy rules that are defined by the `PolicyResolver` in the PU policy.

# Give it a spin

To get started and try it out for yourself, we packaged a simple example into a docker container. [we packaged a simple example into a docker container. ](https://github.com/aporeto-inc/trireme/tree/master/example)

# Defining Your Own Policy

Trireme allows you to define any type of identity attributes and policies to associate with PUs.
In order to define your own policies and identities, you need to implement a PolicyResolver interface that will receive calls from Trireme whenever a policy resolution is required.

# PolicyResolver Implementation

A couple of Helpers are provided as part of the `configurator` packages that loads all of Trireme’s modules with the most common settings:

* `NewPSKTriremeWithDockerMonitor` loads Trireme with the default Docker Monitor. A PreSharedKey is used for remote node signature verification.


* `NewPKITriremeWithDockerMonitor` loads Trireme with the default Docker Monitor. ECDSA is used for signatures. In this case, a publicKeyAdder interface is returned. This interface is used to populate the certificates of the remote nodes.


In parameter to the helper of your choice, you need to give your own `PolicyResolver` interface implementation


* `ResolvePolicy(context string, runtimeInfo policy.RuntimeReader) (*policy.PUPolicy, error)` is called by Trireme in order to Resolve policies for specific ProcessingUnit runtimes that was just created.


* `HandleDeletePU(context string) error` is called by Trireme whenever a ProcessingUnit is stopped/deleted.


* `SetPolicyUpdater(pu trireme.PolicyUpdater) error` is called by Trireme in order to provide a callback pointer in case a Policy needs to be explicitely updated by the PolicyResolver.


The `PolicyResolver` can then issue explicit calls to UpdatePolicy in order to push a policyUpdate for an already running ProcessingUnit.

# License

The Trireme package, although written in Go currently uses the libnetfilter-queue library:
http://www.netfilter.org/projects/libnetfilter_queue/

This library provides the API to the Linux Kernel for interfacing with the NFQUEUE module
that transfers packets to user space for processing. Since this library is provided
under the GPL v2 license, and is linked with the rest of the Trireme code through CGO
we are also releasing this code with a GPL v2 license.

We are taking this step to protect any users of the library from an accidental violation
of the GPL guidelines.
