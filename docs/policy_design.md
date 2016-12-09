# Policy design in Trireme

Trireme includes a powerful policy language that defines explicitely what is allowed and not allowed.
This document aims to explain the basic concepts behind the Trireme policies and how to get started to define your own policies.

# Trireme Cluster

When using Trireme, two different perimeters are defined:
* Trireme endpoints is the set of all Processing Units (typically represents a container) that will get policed through Trireme as described in the next subsection. Trireme Endpoints get policed through `Trireme Internal Policies`
* Outside world: Everything else that is not being policed through Trireme agent. Those other endpoints get policed through more traditionnal  `External policies`

The complex and granular Trireme policies can only be applied if both the receiver and destination are being part of the Trireme endpoints.
In any other cases, a standard set of ACLs will be applied in egress and ingress.

## Trireme CIDR

Trireme is typically installed inside a private cluster. This cluster is a large set of servers under the same administrative control. Each node part of the cluster will get one Trireme agent installed.
We recommend that the endpoints used inside the private Trireme cluster use a well-defined Network CIDR.
The endpoints addresses are the Processing Unit (typically docker) IPs that will be used on your cluster and that will be policed through the Trireme agent.
The typical server on which the Trireme agent runs is typically not an endpoint, but the Docker containers that will run on that servers are endpoints.

This can be for example `10.0.0.0/8` and `172.17.0.0/16` It is referred to as the `Trireme CIDRs` and can be composed of a large set of independent CIDRs.

Those `Trireme CIDRs` is given as parameter to the Trireme agent at startup. The agent uses those CIDRs to decide if a socket Endpoint is going to be inside your Trireme cluster, and therefore if there is a need to add the Trireme metadata to the socket.

## Excluding IPs from `Trireme CIDRs` cluster.

In some specific use-case you want to be able to define a set of CIDRs for Trireme with the exception of a couple of well defined subnets or/and IPs. In order to achieve this, Trireme supports an Exclusion API that can exclude specific endpoints out of the general `Trireme CIDRs` dynamically during runtime.

Any set of IPs in the `Trireme CIDRs` that are not going to get policed through the agent need to be explicitely removed through this exclusion API. This API is defined in supervisor/interfaces.go:


```go
// An Excluder can add/remove specific IPs that are not part of Trireme.
type Excluder interface {

	// AddExcludedIP adds an exception for the destination parameter IP, allowing all the traffic.
	AddExcludedIP(ip string) error

	// RemoveExcludedIP removes the exception for the destination IP given in parameter.
	RemoveExcludedIP(ip string) error
}
```


# Whitelist model for Trireme

Trireme uses a whitelist model. That is, everything that is not explicitely allowed will be denied.

# General logic for policy application.

For Traffic reaching the Processing Unit, the following logic is applied:
```
- If traffic source is part of Trireme CIDRs:
    - If traffic is matched through one of the Trireme rules:
        - If action is ALLOW: Allow traffic.
        - If action is DROP: Drop traffic.
    - Drop unmatched traffic
- If traffic source matches one of the Network ACLs:
    - If action is ALLOW: Allow traffic.
    - If action is DROP: Drop traffic.
- Drop unmatched traffic
```

For traffic exiting the Processing Unit, the following logic is applied:

```
- If traffic destination is part of Trireme CIDRs:
    - Allow traffic (Add Trireme information to the TCP session)
- If traffic destination matches one of the App. ACLs:
    - If action is ALLOW: Allow traffic.
    - If action is DROP: Drop traffic.
- Drop unmatched traffic
```

# Policies for Trireme traffic

# Policies for External traffic.
