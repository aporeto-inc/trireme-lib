// +build !linux

//Package nsenter for switching namespaces
package nsenter

//This package should only run on linux
//Don't test functionality of this package on non linux platforms as
//the setns call is not available there
