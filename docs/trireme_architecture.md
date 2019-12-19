#Trireme Architecture

Trireme takes a different approach to application segmentation by treating the problem as what it is: an authentication and authorization problem. Every application component, such as process, a container, a Kubernetes POD, has an identity.  A segmentation function is a simple policy that defines identities of the endpoints that are allowed to communicate with each other. 

By following this approach instead of managing either IP addresses/port numbers or ACL five-tuple rules, both of which have limited context and are ephemeral by definition, we deal with security policy as a function of identities. This allows us to scale to very large systems, decouple networking from security, and streamline the operational models. 

Indeed, networking is simplified to a transport layer that can use a flat L3 network structure and ignore complex routing protocols. At its simplest form, every container host gets a layer-3 subnet.  As such, there is no need for any route advertisements or route distribution with every container activation.  You can see [the default Kubernetes network architecture] (https://github.com/kubernetes/kubernetes/blob/master/docs/design/networking.md) for an example.

One could argue that identity and policy are complex mechanisms;however, some key components allow us to implement this identity-based application segmentation at the scale that we outline in the next sections.  Specifically: 

1. How do we determine identity and manage policy?
2. How do we insert end-to-end authentication and authorization in applications that we do not control?
3. What is the security model that we can achieve with such a mechanism?

##Identity and Policy Management 

Determining and distributing workload identity can be achieved in multiple ways. If we focus on cloud-native environments where an orchestrator like Kubernetes is used for deploying containers, then identity is  simple to define:  Together with orchestrating the workload, the orchestrator can distribute the identity. 

One could, for example, distribute private/public key pairs to each workload.  Subsequently, the certificate will automatically define the identity of the workload.  However, such an identity is not very useful in policy definition.  One would need to set access policies based on specific workload identities that can change regularly. Imagine, for example, if identity was simply the UUID of the container.  Mapping the container to roles or authorization policies would be challenging by itself.

An alternative approach is to define identity as a collection of attributes that describe a workload. For example, in a container environment, the labels associated with a container can become the identity description. In a Kubernetes cluster, the Kubernetes label selectors can define the identity.  In the Trireme context, we define identity simply as a collection of attributes that describe a workload; moreover, we allow users of the library to determine how  identity attributes are created. For example, attributes can be metadata labels, users that activated the service, or even IP addresses in case someone wants to create a policy that takes IP information into account. 

Once identity is defined as a collection of attributes, it is straightforward to start thinking about authorization as an extension of Attribute-Based Access Control (ABAC).  An authorization policy is just defined as a logical relation between attributes. For example, if a workload is identified with a label “environment=production”, an authorization policy can be “Accept traffic from workloads with “environment=production.”  At its simple form, one can achieve isolation with just a single policy that allows connectivity when two entities have the same labels.  In this way, managing isolation is achieved by just managing the label namespace. 

The Kubernetes Network Policy extension uses a very similar approach and defines access control rules as a function of label selectors. As a result, using Trireme in a Kubernetes environment is a straightforward mapping of label selectors to identities and Network Policies to authorization policies. 

##Transparent Enforcement of Authorization

Enforcing an authorization process for any application has its specific challenges. In some environments, organizations have the freedom to mandate the use of specific RPC libraries for all their components. In these environments, one could enforce the authorization step in the library and be done with it.  In fact, some indications are that certain web-scale providers are doing just this.

Unfortunately, however, for the majority of software deployments, this is not possible because applications use external components and a full control of the software stack is not a viable choice. Therefore, we need a mechanism that can transparently insert end-to-end authorization without modifying applications. Interestingly enough, the IETF community attempted something like that several years ago (see https://tools.ietf.org/html/draft-ietf-cipso-ipsecurity-01) by encoding segmentation information as IP header options. Unfortunately, most modern high-speed routers tend to drop or not process IP options because of the increased overhead. 

In Trireme, we chose to overlay the authorization step in the TCP connection setup protocol with a very simple approach.  Once identity has been defined and cryptographically signed, it can be communicated to the other parties during the Syn/SynAck negotiation as a payload that the application never sees. To achieve this, we have implemented a TCP Authorization Proxy that encapsulates identity in the connection setup packets and allows the two ends to cryptographically verify the validity of the identity attributes and enable connection establishment based on mutual, end-to-end authorization.  In other words, a Syn packet is accepted if and only if it carries a valid identity and the receiving identity is authorized to receive traffic from the given source. Similarly, a SynAck packet is accepted if and only if the identity is valid and the policy allows such a connection. Our proxy implementation only captures/modifies the connection establishment packets and releases all other packets to the kernel for forwarding. 

There are several other benefits of this implementation.  Namely,
- The method does not require any modifications in the application stack or Linux kernel.
- TCP offloads and the TCP negotiation and protocols just work as designed, significantly improving performance over tunneling mechanisms. 
- Although there is an increased connection setup latency, this increase does not require additional round-trip times in the - - TCP negotiation. 
- Since only connection setup packets are processed in the user space the performance impact is minimized. 

##Security Model

The security protection that can be provided with Trireme is significantly more robust than any IP-based mechanism. The classic problem that some Trireme users are solving already is that they operate in environments that they do not trust the network infrastructure. With implementations that tie identity to IP addresses only, it is easy for an attacker that takes control of the network to spoof IP addresses and gain access to applications without authorization. The Trireme approach enforces end-to-end authorization, and the risk of a man-in-the-middle attack is limited to someone taking complete control of the end-system.

Indeed, the Trireme protocol implements a three-way handshake that includes nonces (random numbers) at every step of the negotiation to defend against man-in-the-middle and replay or spoofing attacks.  

##Kubernetes Integration

Together with Trireme, we also provide a Kubernetes integration that implements the Network Policy API without any centralized controllers or coordinated state.  An instance of Trireme runs on every minion, deployed through daemon sets. This local instance listens to the relevant APIs (policies, namespace changes), and POD activation events. When a POD is instantiated, the local instance associates an identity with the POD based on the labels and implements the authorization policy in a completely distributed manner.  From a deployment standpoint, the only requirement is the daemon set deployment. 

Note that the integration can be extended easily to federated clusters and cross NAT boundaries since IP addresses are of no importance. 
