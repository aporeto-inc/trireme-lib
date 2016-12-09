# Policy design in Trireme

Trireme includes a powerful policy language that defines explicitely what is allowed and not allowed.
This document aims to explain the basic concepts behind the Trireme policies and how to get started to define your own policies.

As a user of the Trireme library, you need to implement a `Policy Resolver` interface that will fully define the policies that will apply to your traffic.

The example part of Trireme can be used as a starting point for implementing your own `Policy Resolver`

# Trireme Cluster

When using Trireme, two different perimeters are defined:
* Trireme endpoints is the set of all Processing Units (typically represents a container) that will get policed through Trireme as described in the next subsection. Trireme Endpoints get policed through `Trireme Internal Policies`
* Outside world: Everything else that is not being policed through Trireme agent. Those other endpoints get policed through more traditional  `External policies`

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

# Policies for Trireme traffic.

Traffic flowing inside a cluster between two endpoints that are both policed by Trireme is subject to the Trireme policies.

Those policies rely heavily on a set of metadata identity that is sent as part of the Trireme traffic and decapsulated/encapsulated by the endpoint agents.
Those metadata are labels in the form of `Key:values` and are defined by the  Policy Resolver.
Each Processing Unit will have a set of those labels associated.
Each processing Unit also got a set of Trireme Policies that define which remote Trireme processing units are allowed to connect to the local processing unit.

The Trireme policy is defined as a logical set of `OR` Rules that are each defined as `AND` Clauses:
The action of a Trireme policy is applied IF at least one of the Rules is matched successfully. (Logical `OR`)
In order for a rule to be matched successfully, each clause inside the rule needs to be successfully matched (Logical `AND`)

Each clause is built as a `Key`, Set of `Values` and `Operator`.
Each clause translated to a binary TRUE or FALSE.
The following operations are supported:

* `Equal` returns true if the PU got a label associated to the `Key` with a `value` equal to one of the `values` defined in the policy.
Example:
The clause
```
KEY: App
VALUE: {'nginx', 'centos', 'mysql'}
OPERATOR: `Equal`
```
will return TRUE for the following PU metadata:
```
Image:centos
App:centos
owner:admin
```

will return FALSE for the following PU metadata:
```
Image:server
owner:root
```

* `NotEqual` returns true if the PU got a label associated to the `Key` with a `value` NOT equal to one of the `values` defined in the policy
Example:
The clause
```
KEY: App
VALUE: {'nginx', 'centos', 'mysql'}
OPERATOR: `NotEqual`
```
will return FALSE for the following PU metadata:
```
Image:centos
App:centos
owner:admin
```

will return TRUE for the following PU metadata:
```
Image:server
owner:root
```

will return TRUE for the following PU metadata:
```
Image:server
owner:root
App:redis
```

* `KeyExists` returns true if the PU got a label with  that key in it.

Example:
The clause
```
KEY: App
VALUE: *
OPERATOR: `KeyExists`
```
will return TRUE for the following PU metadata:
```
Image:centos
App:abcd
owner:admin
```

will return FALSE for the following PU metadata:
```
Image:server
owner:root
```

* `KeyNotExists` returns true if the PU doesn't have a label with the specified key in it.

Example:
The clause
```
KEY: App
VALUE: *
OPERATOR: `KeyNotExists`
```
will return FALSE for the following PU metadata:
```
Image:centos
App:centos
owner:admin
```

will return TRUE for the following PU metadata:
```
Image:server
owner:root
```

# Special tags for Port matching.

Trireme introduces dynamically an extra label per TCP connection that represents the TCP destination port.
That extra label got the following format:
```
@port:xx
```
This label can then be used for matching in any of the previously defined rules, like any other usual label.

# Policies for External traffic.

If the source or receiver endpoint is not part of the Trireme CIDRs, then the Policies for external traffic are used.
Those policies are defined as usual Network ACLs with Network and port matches.

For each Processing Unit, the following two policies are defined:
* Application policy: The allowed traffic that originates from that processing unit.

* Net policy: The traffic that is allowed to reach the Processing unit from the network.

Both these policies take the format of a set of (Network/Port-range/Protocol type).
* Network is the CIDR of the network traffic we want to allow (Example: `192.169.0.0/16`)
* Port-range can be a single port or any range of port (Example: `100-200`)
* Protocol type is the L4 protocol type (Must be one of `TCP`/`UDP`/`ICMP`)
