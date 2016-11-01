# Secure Application Segmentation

The concept of segmentation, or separating applications in different domains, is one of the most widely used security practices. Segmentation protects application deployments by minimizing lateral movement of attackers or reducing the blast radius by containing a system component compromise within a small subsystem.

Over the last several years segmentation was often translated to a network isolation problem where, by restricting network reachability, we could achieve isolation. VLANs, VXLAN, MPLS, firewall ACLs, host ACLs are all trying to segment applications by associating application context to an IP address/port and then managing reachability between two components by controlling routing or five-tuple rules.

Network segmentation approaches had to solve two problems:

1. Associate a workload with an IP address and port number; and
2. create the necessary network structures or reachability rules to limit communication.

These techniques worked well in traditional server environments and virtual machine deployments where the creation of new servers or VMs is an infrequent event. When new servers are created they are placed in the proper network segment (VLAN or even AWS VPC) or the proper ACL rules are added to the host. However, as we move to containers, microservices, and serverless architectures, scaling this model has become increasingly more complex and cumbersome. Because we are shifting away from monolithic architectures towards microservice architectures, the rate of instantiation of new application components is increasing by orders of magnitude.

Additionally, several of these techniques introduce significant complexity in the network by requiring gateways, middle-boxes, and other devices to co-ordinate this segmentation and deal with the problems of reachability outside the simple domain of a network segment.

With Trireme we take an entirely different approach to segmentation issues by introducing transparent authentication and authorization in any communication between workloads. Instead of using an IP address as the identifier of a workload, we use a proper identity mechanism. Instead of using ACLs and network reachability for controlling communication between applications, we introduce an end-to-end authentication and authorization step.

Transitioning to such a model comes with some fundamental benefits for any deployment:

1. Security is decoupled from network IP addressing, allowing operators to optimize their network (transport) with simple techniques and delegate security to the application layer where it belongs.
2. The network architecture for large scale container deployments can be reduced to a simple L3 network. In short:  no VLANs, no tunnels, no firewall rules, no ACLs, no fast route updates that will never converge. Crossing domains, NAT, IPv4/IPv6 translations are orthogonal and irrelevant to the end-to-end isolation.
3. Security is much stronger since workloads are isolated by cryptographically verified end-to-end authentication and authorization that can defend against spoofing, man-in-the-middle, and replay attacks.
4. Developers do not need to deal or depend on network segments and IP address assignments. An isolation segment can be created simply by attaching an identity property to a workload.
5. The scheme does not require any control plane. The technique is completely distributed with no shared state and no eventual consistency problems.

The biggest value of Trireme is its simplicity: simple deployment and simple operations. One would naturally ask the question why this has never be done before. Actually,similar techniques have been attempted in the past but with less success. The first example of such a technique was [the CIPSO standard] (https://tools.ietf.org/html/draft-ietf-cipso-ipsecurity-01). The idea, embraced by US government agencies, Trusted Solaris, and SELinux, was was to carry applicationcontext in IP options. There are several differences of Trireme compared to this initial approach:

1. IP options are dropped or improperly handled by the majority of high-speed routers and switches;
2. although some application context is carried in packets, this context is rather limited and not cryptographically protected.

The benefit we have today is that cloud deployments enable the automatic distribution of identity. Systems like Kubernetes make it much simpler to distribute and manage workload identity, and it is exactly these capabilities that make the Trireme approach attractive and viable.

We are happy to share Trireme with the community and solicit feedback. We believe that we are at the first stages of a transformation where the transition to cloud native deployments will become a catalyst for stronger security. Trireme is just the first step.
