// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.6.1
// source: monitor.proto

package protos

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type CNIContainerEventRequest_Type int32

const (
	CNIContainerEventRequest_ADD    CNIContainerEventRequest_Type = 0
	CNIContainerEventRequest_DELETE CNIContainerEventRequest_Type = 1
)

// Enum value maps for CNIContainerEventRequest_Type.
var (
	CNIContainerEventRequest_Type_name = map[int32]string{
		0: "ADD",
		1: "DELETE",
	}
	CNIContainerEventRequest_Type_value = map[string]int32{
		"ADD":    0,
		"DELETE": 1,
	}
)

func (x CNIContainerEventRequest_Type) Enum() *CNIContainerEventRequest_Type {
	p := new(CNIContainerEventRequest_Type)
	*p = x
	return p
}

func (x CNIContainerEventRequest_Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (CNIContainerEventRequest_Type) Descriptor() protoreflect.EnumDescriptor {
	return file_monitor_proto_enumTypes[0].Descriptor()
}

func (CNIContainerEventRequest_Type) Type() protoreflect.EnumType {
	return &file_monitor_proto_enumTypes[0]
}

func (x CNIContainerEventRequest_Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use CNIContainerEventRequest_Type.Descriptor instead.
func (CNIContainerEventRequest_Type) EnumDescriptor() ([]byte, []int) {
	return file_monitor_proto_rawDescGZIP(), []int{1, 0}
}

type RunCContainerEventRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CommandLine []string `protobuf:"bytes,1,rep,name=commandLine,proto3" json:"commandLine,omitempty"` // the full commandline of the runc command incl. flags, etc. - this is expected to come from `os.Args`
}

func (x *RunCContainerEventRequest) Reset() {
	*x = RunCContainerEventRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_monitor_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RunCContainerEventRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RunCContainerEventRequest) ProtoMessage() {}

func (x *RunCContainerEventRequest) ProtoReflect() protoreflect.Message {
	mi := &file_monitor_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RunCContainerEventRequest.ProtoReflect.Descriptor instead.
func (*RunCContainerEventRequest) Descriptor() ([]byte, []int) {
	return file_monitor_proto_rawDescGZIP(), []int{0}
}

func (x *RunCContainerEventRequest) GetCommandLine() []string {
	if x != nil {
		return x.CommandLine
	}
	return nil
}

type CNIContainerEventRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type         CNIContainerEventRequest_Type `protobuf:"varint,1,opt,name=type,proto3,enum=protos.CNIContainerEventRequest_Type" json:"type,omitempty"`
	ContainerID  string                        `protobuf:"bytes,2,opt,name=containerID,proto3" json:"containerID,omitempty"`
	NetnsPath    string                        `protobuf:"bytes,3,opt,name=netnsPath,proto3" json:"netnsPath,omitempty"`
	PodName      string                        `protobuf:"bytes,4,opt,name=podName,proto3" json:"podName,omitempty"`
	PodNamespace string                        `protobuf:"bytes,5,opt,name=podNamespace,proto3" json:"podNamespace,omitempty"`
}

func (x *CNIContainerEventRequest) Reset() {
	*x = CNIContainerEventRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_monitor_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CNIContainerEventRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CNIContainerEventRequest) ProtoMessage() {}

func (x *CNIContainerEventRequest) ProtoReflect() protoreflect.Message {
	mi := &file_monitor_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CNIContainerEventRequest.ProtoReflect.Descriptor instead.
func (*CNIContainerEventRequest) Descriptor() ([]byte, []int) {
	return file_monitor_proto_rawDescGZIP(), []int{1}
}

func (x *CNIContainerEventRequest) GetType() CNIContainerEventRequest_Type {
	if x != nil {
		return x.Type
	}
	return CNIContainerEventRequest_ADD
}

func (x *CNIContainerEventRequest) GetContainerID() string {
	if x != nil {
		return x.ContainerID
	}
	return ""
}

func (x *CNIContainerEventRequest) GetNetnsPath() string {
	if x != nil {
		return x.NetnsPath
	}
	return ""
}

func (x *CNIContainerEventRequest) GetPodName() string {
	if x != nil {
		return x.PodName
	}
	return ""
}

func (x *CNIContainerEventRequest) GetPodNamespace() string {
	if x != nil {
		return x.PodNamespace
	}
	return ""
}

type ContainerEventResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ErrorMessage string `protobuf:"bytes,1,opt,name=errorMessage,proto3" json:"errorMessage,omitempty"` // errorMessage will be empty on success, and have an error message set only on an error
}

func (x *ContainerEventResponse) Reset() {
	*x = ContainerEventResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_monitor_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ContainerEventResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerEventResponse) ProtoMessage() {}

func (x *ContainerEventResponse) ProtoReflect() protoreflect.Message {
	mi := &file_monitor_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerEventResponse.ProtoReflect.Descriptor instead.
func (*ContainerEventResponse) Descriptor() ([]byte, []int) {
	return file_monitor_proto_rawDescGZIP(), []int{2}
}

func (x *ContainerEventResponse) GetErrorMessage() string {
	if x != nil {
		return x.ErrorMessage
	}
	return ""
}

var File_monitor_proto protoreflect.FileDescriptor

var file_monitor_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x3d, 0x0a, 0x19, 0x52, 0x75, 0x6e, 0x43, 0x43, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c,
	0x69, 0x6e, 0x65, 0x22, 0xf0, 0x01, 0x0a, 0x18, 0x43, 0x4e, 0x49, 0x43, 0x6f, 0x6e, 0x74, 0x61,
	0x69, 0x6e, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x39, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x25,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x43, 0x4e, 0x49, 0x43, 0x6f, 0x6e, 0x74, 0x61,
	0x69, 0x6e, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x2e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x63,
	0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x44, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x44, 0x12, 0x1c, 0x0a,
	0x09, 0x6e, 0x65, 0x74, 0x6e, 0x73, 0x50, 0x61, 0x74, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x6e, 0x65, 0x74, 0x6e, 0x73, 0x50, 0x61, 0x74, 0x68, 0x12, 0x18, 0x0a, 0x07, 0x70,
	0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x6f,
	0x64, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x70, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65,
	0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x70, 0x6f, 0x64,
	0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x22, 0x1b, 0x0a, 0x04, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x07, 0x0a, 0x03, 0x41, 0x44, 0x44, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x44, 0x45,
	0x4c, 0x45, 0x54, 0x45, 0x10, 0x01, 0x22, 0x3c, 0x0a, 0x16, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69,
	0x6e, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x22, 0x0a, 0x0c, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x32, 0xa7, 0x01, 0x0a, 0x04, 0x52, 0x75, 0x6e, 0x43, 0x12, 0x44, 0x0a,
	0x10, 0x52, 0x75, 0x6e, 0x63, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x53, 0x74, 0x61, 0x72, 0x74, 0x65,
	0x64, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74,
	0x79, 0x22, 0x00, 0x12, 0x59, 0x0a, 0x12, 0x52, 0x75, 0x6e, 0x43, 0x43, 0x6f, 0x6e, 0x74, 0x61,
	0x69, 0x6e, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x21, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x73, 0x2e, 0x52, 0x75, 0x6e, 0x43, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x32, 0x5e,
	0x0a, 0x03, 0x43, 0x4e, 0x49, 0x12, 0x57, 0x0a, 0x11, 0x43, 0x4e, 0x49, 0x43, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x20, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x73, 0x2e, 0x43, 0x4e, 0x49, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x0a,
	0x5a, 0x08, 0x2e, 0x3b, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_monitor_proto_rawDescOnce sync.Once
	file_monitor_proto_rawDescData = file_monitor_proto_rawDesc
)

func file_monitor_proto_rawDescGZIP() []byte {
	file_monitor_proto_rawDescOnce.Do(func() {
		file_monitor_proto_rawDescData = protoimpl.X.CompressGZIP(file_monitor_proto_rawDescData)
	})
	return file_monitor_proto_rawDescData
}

var file_monitor_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_monitor_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_monitor_proto_goTypes = []interface{}{
	(CNIContainerEventRequest_Type)(0), // 0: protos.CNIContainerEventRequest.Type
	(*RunCContainerEventRequest)(nil),  // 1: protos.RunCContainerEventRequest
	(*CNIContainerEventRequest)(nil),   // 2: protos.CNIContainerEventRequest
	(*ContainerEventResponse)(nil),     // 3: protos.ContainerEventResponse
	(*empty.Empty)(nil),                // 4: google.protobuf.Empty
}
var file_monitor_proto_depIdxs = []int32{
	0, // 0: protos.CNIContainerEventRequest.type:type_name -> protos.CNIContainerEventRequest.Type
	4, // 1: protos.RunC.RuncProxyStarted:input_type -> google.protobuf.Empty
	1, // 2: protos.RunC.RunCContainerEvent:input_type -> protos.RunCContainerEventRequest
	2, // 3: protos.CNI.CNIContainerEvent:input_type -> protos.CNIContainerEventRequest
	4, // 4: protos.RunC.RuncProxyStarted:output_type -> google.protobuf.Empty
	3, // 5: protos.RunC.RunCContainerEvent:output_type -> protos.ContainerEventResponse
	3, // 6: protos.CNI.CNIContainerEvent:output_type -> protos.ContainerEventResponse
	4, // [4:7] is the sub-list for method output_type
	1, // [1:4] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_monitor_proto_init() }
func file_monitor_proto_init() {
	if File_monitor_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_monitor_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RunCContainerEventRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_monitor_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CNIContainerEventRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_monitor_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ContainerEventResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_monitor_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   2,
		},
		GoTypes:           file_monitor_proto_goTypes,
		DependencyIndexes: file_monitor_proto_depIdxs,
		EnumInfos:         file_monitor_proto_enumTypes,
		MessageInfos:      file_monitor_proto_msgTypes,
	}.Build()
	File_monitor_proto = out.File
	file_monitor_proto_rawDesc = nil
	file_monitor_proto_goTypes = nil
	file_monitor_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// RunCClient is the client API for RunC service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type RunCClient interface {
	// RuncProxyStarted is called by the PCC agent once the runc proxy has been started
	RuncProxyStarted(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*empty.Empty, error)
	// ContainerEvent will be invoked by the runc proxy on the following events at this point:
	// - ‘runc start’
	// - 'runc delete'
	RunCContainerEvent(ctx context.Context, in *RunCContainerEventRequest, opts ...grpc.CallOption) (*ContainerEventResponse, error)
}

type runCClient struct {
	cc grpc.ClientConnInterface
}

func NewRunCClient(cc grpc.ClientConnInterface) RunCClient {
	return &runCClient{cc}
}

func (c *runCClient) RuncProxyStarted(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/protos.RunC/RuncProxyStarted", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *runCClient) RunCContainerEvent(ctx context.Context, in *RunCContainerEventRequest, opts ...grpc.CallOption) (*ContainerEventResponse, error) {
	out := new(ContainerEventResponse)
	err := c.cc.Invoke(ctx, "/protos.RunC/RunCContainerEvent", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RunCServer is the server API for RunC service.
type RunCServer interface {
	// RuncProxyStarted is called by the PCC agent once the runc proxy has been started
	RuncProxyStarted(context.Context, *empty.Empty) (*empty.Empty, error)
	// ContainerEvent will be invoked by the runc proxy on the following events at this point:
	// - ‘runc start’
	// - 'runc delete'
	RunCContainerEvent(context.Context, *RunCContainerEventRequest) (*ContainerEventResponse, error)
}

// UnimplementedRunCServer can be embedded to have forward compatible implementations.
type UnimplementedRunCServer struct {
}

func (*UnimplementedRunCServer) RuncProxyStarted(context.Context, *empty.Empty) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RuncProxyStarted not implemented")
}
func (*UnimplementedRunCServer) RunCContainerEvent(context.Context, *RunCContainerEventRequest) (*ContainerEventResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RunCContainerEvent not implemented")
}

func RegisterRunCServer(s *grpc.Server, srv RunCServer) {
	s.RegisterService(&_RunC_serviceDesc, srv)
}

func _RunC_RuncProxyStarted_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RunCServer).RuncProxyStarted(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protos.RunC/RuncProxyStarted",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RunCServer).RuncProxyStarted(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _RunC_RunCContainerEvent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RunCContainerEventRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RunCServer).RunCContainerEvent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protos.RunC/RunCContainerEvent",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RunCServer).RunCContainerEvent(ctx, req.(*RunCContainerEventRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _RunC_serviceDesc = grpc.ServiceDesc{
	ServiceName: "protos.RunC",
	HandlerType: (*RunCServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RuncProxyStarted",
			Handler:    _RunC_RuncProxyStarted_Handler,
		},
		{
			MethodName: "RunCContainerEvent",
			Handler:    _RunC_RunCContainerEvent_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "monitor.proto",
}

// CNIClient is the client API for CNI service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type CNIClient interface {
	// ContainerEvent will be invoked by the CNI plugin on the following events at this point:
	// - ‘cmdADD start’
	// - 'cmdDEL delete'
	CNIContainerEvent(ctx context.Context, in *CNIContainerEventRequest, opts ...grpc.CallOption) (*ContainerEventResponse, error)
}

type cNIClient struct {
	cc grpc.ClientConnInterface
}

func NewCNIClient(cc grpc.ClientConnInterface) CNIClient {
	return &cNIClient{cc}
}

func (c *cNIClient) CNIContainerEvent(ctx context.Context, in *CNIContainerEventRequest, opts ...grpc.CallOption) (*ContainerEventResponse, error) {
	out := new(ContainerEventResponse)
	err := c.cc.Invoke(ctx, "/protos.CNI/CNIContainerEvent", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CNIServer is the server API for CNI service.
type CNIServer interface {
	// ContainerEvent will be invoked by the CNI plugin on the following events at this point:
	// - ‘cmdADD start’
	// - 'cmdDEL delete'
	CNIContainerEvent(context.Context, *CNIContainerEventRequest) (*ContainerEventResponse, error)
}

// UnimplementedCNIServer can be embedded to have forward compatible implementations.
type UnimplementedCNIServer struct {
}

func (*UnimplementedCNIServer) CNIContainerEvent(context.Context, *CNIContainerEventRequest) (*ContainerEventResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CNIContainerEvent not implemented")
}

func RegisterCNIServer(s *grpc.Server, srv CNIServer) {
	s.RegisterService(&_CNI_serviceDesc, srv)
}

func _CNI_CNIContainerEvent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CNIContainerEventRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CNIServer).CNIContainerEvent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protos.CNI/CNIContainerEvent",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CNIServer).CNIContainerEvent(ctx, req.(*CNIContainerEventRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _CNI_serviceDesc = grpc.ServiceDesc{
	ServiceName: "protos.CNI",
	HandlerType: (*CNIServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CNIContainerEvent",
			Handler:    _CNI_CNIContainerEvent_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "monitor.proto",
}
