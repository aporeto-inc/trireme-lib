# Trireme

Simple, scalable and secure application segmentation

Trireme is a generic library that enables end-to-end authentication and authorization for containers. Every processing unit is identified
by its attributes (labels, image,  etc ) or other environments variables. Two containers can only talk to each other if a
policy between the attributes allows such communication.

The library is extensible and it allows the custom implementation of policies,  extractors of attributors, additional modules for implementation in addition to authentication and authorization, as well external logging modules.  The trireme library can be  
integrated with  orchestration systems like Kubernetes or Mesos,  or it can be run in standalone mode with simple docker containers.

# License

The Trireme package, although written in Go currently uses the libnetfilter-queue library:
http://www.netfilter.org/projects/libnetfilter_queue/

This library provides the API to the Linux Kernel for interfacing with the NFQUEUE module
that transfers packets to user space for processing. Since this library is provided
under the GPL v2 license, and is linked with the rest of the Trireme code through CGO
we are also releasing this code with a GPL v2 license.

We are taking this step to protect any users of the library from an accidental violation
of the GPL guidelines. 
