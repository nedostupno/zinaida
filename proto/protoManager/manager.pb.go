// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        (unknown)
// source: manager.proto

package protoManager

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
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

type GetNodeResponse_Error_Code int32

const (
	GetNodeResponse_Error_INTERNAL_ERROR GetNodeResponse_Error_Code = 0
	GetNodeResponse_Error_NODE_NOT_EXIST GetNodeResponse_Error_Code = 1
)

// Enum value maps for GetNodeResponse_Error_Code.
var (
	GetNodeResponse_Error_Code_name = map[int32]string{
		0: "INTERNAL_ERROR",
		1: "NODE_NOT_EXIST",
	}
	GetNodeResponse_Error_Code_value = map[string]int32{
		"INTERNAL_ERROR": 0,
		"NODE_NOT_EXIST": 1,
	}
)

func (x GetNodeResponse_Error_Code) Enum() *GetNodeResponse_Error_Code {
	p := new(GetNodeResponse_Error_Code)
	*p = x
	return p
}

func (x GetNodeResponse_Error_Code) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (GetNodeResponse_Error_Code) Descriptor() protoreflect.EnumDescriptor {
	return file_manager_proto_enumTypes[0].Descriptor()
}

func (GetNodeResponse_Error_Code) Type() protoreflect.EnumType {
	return &file_manager_proto_enumTypes[0]
}

func (x GetNodeResponse_Error_Code) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use GetNodeResponse_Error_Code.Descriptor instead.
func (GetNodeResponse_Error_Code) EnumDescriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{4, 0, 0}
}

type LoginResponse_Error_Code int32

const (
	LoginResponse_Error_INTERNAL_ERROR LoginResponse_Error_Code = 0
	LoginResponse_Error_INCORRECT_DATA LoginResponse_Error_Code = 1
)

// Enum value maps for LoginResponse_Error_Code.
var (
	LoginResponse_Error_Code_name = map[int32]string{
		0: "INTERNAL_ERROR",
		1: "INCORRECT_DATA",
	}
	LoginResponse_Error_Code_value = map[string]int32{
		"INTERNAL_ERROR": 0,
		"INCORRECT_DATA": 1,
	}
)

func (x LoginResponse_Error_Code) Enum() *LoginResponse_Error_Code {
	p := new(LoginResponse_Error_Code)
	*p = x
	return p
}

func (x LoginResponse_Error_Code) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LoginResponse_Error_Code) Descriptor() protoreflect.EnumDescriptor {
	return file_manager_proto_enumTypes[1].Descriptor()
}

func (LoginResponse_Error_Code) Type() protoreflect.EnumType {
	return &file_manager_proto_enumTypes[1]
}

func (x LoginResponse_Error_Code) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LoginResponse_Error_Code.Descriptor instead.
func (LoginResponse_Error_Code) EnumDescriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{6, 0, 0}
}

type NodeAgent struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id     int64  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Ip     string `protobuf:"bytes,2,opt,name=ip,proto3" json:"ip,omitempty"`
	Domain string `protobuf:"bytes,3,opt,name=domain,proto3" json:"domain,omitempty"`
}

func (x *NodeAgent) Reset() {
	*x = NodeAgent{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NodeAgent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeAgent) ProtoMessage() {}

func (x *NodeAgent) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeAgent.ProtoReflect.Descriptor instead.
func (*NodeAgent) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{0}
}

func (x *NodeAgent) GetId() int64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *NodeAgent) GetIp() string {
	if x != nil {
		return x.Ip
	}
	return ""
}

func (x *NodeAgent) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

type RegistrateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NodeAgent *NodeAgent `protobuf:"bytes,1,opt,name=nodeAgent,proto3" json:"nodeAgent,omitempty"`
}

func (x *RegistrateResponse) Reset() {
	*x = RegistrateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegistrateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegistrateResponse) ProtoMessage() {}

func (x *RegistrateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegistrateResponse.ProtoReflect.Descriptor instead.
func (*RegistrateResponse) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{1}
}

func (x *RegistrateResponse) GetNodeAgent() *NodeAgent {
	if x != nil {
		return x.NodeAgent
	}
	return nil
}

type RegistrateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ip     string `protobuf:"bytes,1,opt,name=ip,proto3" json:"ip,omitempty"`
	Domain string `protobuf:"bytes,2,opt,name=domain,proto3" json:"domain,omitempty"`
}

func (x *RegistrateRequest) Reset() {
	*x = RegistrateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegistrateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegistrateRequest) ProtoMessage() {}

func (x *RegistrateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegistrateRequest.ProtoReflect.Descriptor instead.
func (*RegistrateRequest) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{2}
}

func (x *RegistrateRequest) GetIp() string {
	if x != nil {
		return x.Ip
	}
	return ""
}

func (x *RegistrateRequest) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

type GetNodeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id int64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *GetNodeRequest) Reset() {
	*x = GetNodeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetNodeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetNodeRequest) ProtoMessage() {}

func (x *GetNodeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetNodeRequest.ProtoReflect.Descriptor instead.
func (*GetNodeRequest) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{3}
}

func (x *GetNodeRequest) GetId() int64 {
	if x != nil {
		return x.Id
	}
	return 0
}

type GetNodeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Result:
	//	*GetNodeResponse_NodeAgent
	//	*GetNodeResponse_Error_
	Result isGetNodeResponse_Result `protobuf_oneof:"result"`
}

func (x *GetNodeResponse) Reset() {
	*x = GetNodeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetNodeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetNodeResponse) ProtoMessage() {}

func (x *GetNodeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetNodeResponse.ProtoReflect.Descriptor instead.
func (*GetNodeResponse) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{4}
}

func (m *GetNodeResponse) GetResult() isGetNodeResponse_Result {
	if m != nil {
		return m.Result
	}
	return nil
}

func (x *GetNodeResponse) GetNodeAgent() *NodeAgent {
	if x, ok := x.GetResult().(*GetNodeResponse_NodeAgent); ok {
		return x.NodeAgent
	}
	return nil
}

func (x *GetNodeResponse) GetError() *GetNodeResponse_Error {
	if x, ok := x.GetResult().(*GetNodeResponse_Error_); ok {
		return x.Error
	}
	return nil
}

type isGetNodeResponse_Result interface {
	isGetNodeResponse_Result()
}

type GetNodeResponse_NodeAgent struct {
	NodeAgent *NodeAgent `protobuf:"bytes,1,opt,name=nodeAgent,proto3,oneof"`
}

type GetNodeResponse_Error_ struct {
	Error *GetNodeResponse_Error `protobuf:"bytes,2,opt,name=error,proto3,oneof"`
}

func (*GetNodeResponse_NodeAgent) isGetNodeResponse_Result() {}

func (*GetNodeResponse_Error_) isGetNodeResponse_Result() {}

type LoginRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Username string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
	Password string `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *LoginRequest) Reset() {
	*x = LoginRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoginRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginRequest) ProtoMessage() {}

func (x *LoginRequest) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginRequest.ProtoReflect.Descriptor instead.
func (*LoginRequest) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{5}
}

func (x *LoginRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *LoginRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type LoginResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Result:
	//	*LoginResponse_Jwt
	//	*LoginResponse_Error_
	Result isLoginResponse_Result `protobuf_oneof:"result"`
}

func (x *LoginResponse) Reset() {
	*x = LoginResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoginResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginResponse) ProtoMessage() {}

func (x *LoginResponse) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginResponse.ProtoReflect.Descriptor instead.
func (*LoginResponse) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{6}
}

func (m *LoginResponse) GetResult() isLoginResponse_Result {
	if m != nil {
		return m.Result
	}
	return nil
}

func (x *LoginResponse) GetJwt() *JWT {
	if x, ok := x.GetResult().(*LoginResponse_Jwt); ok {
		return x.Jwt
	}
	return nil
}

func (x *LoginResponse) GetError() *LoginResponse_Error {
	if x, ok := x.GetResult().(*LoginResponse_Error_); ok {
		return x.Error
	}
	return nil
}

type isLoginResponse_Result interface {
	isLoginResponse_Result()
}

type LoginResponse_Jwt struct {
	Jwt *JWT `protobuf:"bytes,1,opt,name=jwt,proto3,oneof"`
}

type LoginResponse_Error_ struct {
	Error *LoginResponse_Error `protobuf:"bytes,2,opt,name=error,proto3,oneof"`
}

func (*LoginResponse_Jwt) isLoginResponse_Result() {}

func (*LoginResponse_Error_) isLoginResponse_Result() {}

type JWT struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccessToken  string `protobuf:"bytes,2,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	RefreshToken string `protobuf:"bytes,3,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
}

func (x *JWT) Reset() {
	*x = JWT{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *JWT) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JWT) ProtoMessage() {}

func (x *JWT) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JWT.ProtoReflect.Descriptor instead.
func (*JWT) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{7}
}

func (x *JWT) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

func (x *JWT) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

type GetNodeResponse_Error struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string                     `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	Code    GetNodeResponse_Error_Code `protobuf:"varint,2,opt,name=code,proto3,enum=protoManager.GetNodeResponse_Error_Code" json:"code,omitempty"`
}

func (x *GetNodeResponse_Error) Reset() {
	*x = GetNodeResponse_Error{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetNodeResponse_Error) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetNodeResponse_Error) ProtoMessage() {}

func (x *GetNodeResponse_Error) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetNodeResponse_Error.ProtoReflect.Descriptor instead.
func (*GetNodeResponse_Error) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{4, 0}
}

func (x *GetNodeResponse_Error) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *GetNodeResponse_Error) GetCode() GetNodeResponse_Error_Code {
	if x != nil {
		return x.Code
	}
	return GetNodeResponse_Error_INTERNAL_ERROR
}

type LoginResponse_Error struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string                   `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	Code    LoginResponse_Error_Code `protobuf:"varint,2,opt,name=code,proto3,enum=protoManager.LoginResponse_Error_Code" json:"code,omitempty"`
}

func (x *LoginResponse_Error) Reset() {
	*x = LoginResponse_Error{}
	if protoimpl.UnsafeEnabled {
		mi := &file_manager_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoginResponse_Error) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginResponse_Error) ProtoMessage() {}

func (x *LoginResponse_Error) ProtoReflect() protoreflect.Message {
	mi := &file_manager_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginResponse_Error.ProtoReflect.Descriptor instead.
func (*LoginResponse_Error) Descriptor() ([]byte, []int) {
	return file_manager_proto_rawDescGZIP(), []int{6, 0}
}

func (x *LoginResponse_Error) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *LoginResponse_Error) GetCode() LoginResponse_Error_Code {
	if x != nil {
		return x.Code
	}
	return LoginResponse_Error_INTERNAL_ERROR
}

var File_manager_proto protoreflect.FileDescriptor

var file_manager_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0c, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x1a, 0x1c, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x43, 0x0a, 0x09, 0x4e,
	0x6f, 0x64, 0x65, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x69, 0x64, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x70, 0x12, 0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61,
	0x69, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
	0x22, 0x4b, 0x0a, 0x12, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x35, 0x0a, 0x09, 0x6e, 0x6f, 0x64, 0x65, 0x41, 0x67,
	0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x52, 0x09, 0x6e, 0x6f, 0x64, 0x65, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x22, 0x3b, 0x0a,
	0x11, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02,
	0x69, 0x70, 0x12, 0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x22, 0x20, 0x0a, 0x0e, 0x47, 0x65,
	0x74, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x69, 0x64, 0x22, 0xa3, 0x02, 0x0a,
	0x0f, 0x47, 0x65, 0x74, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x37, 0x0a, 0x09, 0x6e, 0x6f, 0x64, 0x65, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67,
	0x65, 0x72, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x48, 0x00, 0x52, 0x09,
	0x6e, 0x6f, 0x64, 0x65, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x3b, 0x0a, 0x05, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x4e, 0x6f, 0x64, 0x65, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x48, 0x00, 0x52,
	0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x1a, 0x8f, 0x01, 0x0a, 0x05, 0x45, 0x72, 0x72, 0x6f, 0x72,
	0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x3c, 0x0a, 0x04, 0x63, 0x6f,
	0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x28, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74, 0x4e, 0x6f, 0x64, 0x65, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x2e, 0x43, 0x6f,
	0x64, 0x65, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x22, 0x2e, 0x0a, 0x04, 0x43, 0x6f, 0x64, 0x65,
	0x12, 0x12, 0x0a, 0x0e, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x5f, 0x45, 0x52, 0x52,
	0x4f, 0x52, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e, 0x4e, 0x4f, 0x44, 0x45, 0x5f, 0x4e, 0x4f, 0x54,
	0x5f, 0x45, 0x58, 0x49, 0x53, 0x54, 0x10, 0x01, 0x42, 0x08, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x22, 0x46, 0x0a, 0x0c, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a,
	0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x22, 0x8b, 0x02, 0x0a, 0x0d, 0x4c,
	0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x25, 0x0a, 0x03,
	0x6a, 0x77, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x4a, 0x57, 0x54, 0x48, 0x00, 0x52, 0x03,
	0x6a, 0x77, 0x74, 0x12, 0x39, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x21, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65,
	0x72, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e,
	0x45, 0x72, 0x72, 0x6f, 0x72, 0x48, 0x00, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x1a, 0x8d,
	0x01, 0x0a, 0x05, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x12, 0x3a, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x26, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e,
	0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x45, 0x72,
	0x72, 0x6f, 0x72, 0x2e, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x22, 0x2e,
	0x0a, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x12, 0x0a, 0x0e, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e,
	0x41, 0x4c, 0x5f, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e, 0x49, 0x4e,
	0x43, 0x4f, 0x52, 0x52, 0x45, 0x43, 0x54, 0x5f, 0x44, 0x41, 0x54, 0x41, 0x10, 0x01, 0x42, 0x08,
	0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x4d, 0x0a, 0x03, 0x4a, 0x57, 0x54, 0x12,
	0x21, 0x0a, 0x0c, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65, 0x66, 0x72, 0x65,
	0x73, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x32, 0x94, 0x02, 0x0a, 0x07, 0x6d, 0x61, 0x6e, 0x61,
	0x67, 0x65, 0x72, 0x12, 0x4f, 0x0a, 0x0a, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x65, 0x12, 0x1f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
	0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x20, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65,
	0x72, 0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5f, 0x0a, 0x07, 0x47, 0x65, 0x74, 0x4e, 0x6f, 0x64, 0x65, 0x12,
	0x1c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x47,
	0x65, 0x74, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1d, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x47, 0x65, 0x74,
	0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x17, 0x82, 0xd3,
	0xe4, 0x93, 0x02, 0x11, 0x12, 0x0f, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x73,
	0x2f, 0x7b, 0x69, 0x64, 0x7d, 0x12, 0x57, 0x0a, 0x05, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x12, 0x1a,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x4c, 0x6f,
	0x67, 0x69, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1b, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x15, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x0f, 0x22,
	0x0a, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x3a, 0x01, 0x2a, 0x42, 0x10,
	0x5a, 0x0e, 0x2e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_manager_proto_rawDescOnce sync.Once
	file_manager_proto_rawDescData = file_manager_proto_rawDesc
)

func file_manager_proto_rawDescGZIP() []byte {
	file_manager_proto_rawDescOnce.Do(func() {
		file_manager_proto_rawDescData = protoimpl.X.CompressGZIP(file_manager_proto_rawDescData)
	})
	return file_manager_proto_rawDescData
}

var file_manager_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_manager_proto_msgTypes = make([]protoimpl.MessageInfo, 10)
var file_manager_proto_goTypes = []interface{}{
	(GetNodeResponse_Error_Code)(0), // 0: protoManager.GetNodeResponse.Error.Code
	(LoginResponse_Error_Code)(0),   // 1: protoManager.LoginResponse.Error.Code
	(*NodeAgent)(nil),               // 2: protoManager.NodeAgent
	(*RegistrateResponse)(nil),      // 3: protoManager.RegistrateResponse
	(*RegistrateRequest)(nil),       // 4: protoManager.RegistrateRequest
	(*GetNodeRequest)(nil),          // 5: protoManager.GetNodeRequest
	(*GetNodeResponse)(nil),         // 6: protoManager.GetNodeResponse
	(*LoginRequest)(nil),            // 7: protoManager.LoginRequest
	(*LoginResponse)(nil),           // 8: protoManager.LoginResponse
	(*JWT)(nil),                     // 9: protoManager.JWT
	(*GetNodeResponse_Error)(nil),   // 10: protoManager.GetNodeResponse.Error
	(*LoginResponse_Error)(nil),     // 11: protoManager.LoginResponse.Error
}
var file_manager_proto_depIdxs = []int32{
	2,  // 0: protoManager.RegistrateResponse.nodeAgent:type_name -> protoManager.NodeAgent
	2,  // 1: protoManager.GetNodeResponse.nodeAgent:type_name -> protoManager.NodeAgent
	10, // 2: protoManager.GetNodeResponse.error:type_name -> protoManager.GetNodeResponse.Error
	9,  // 3: protoManager.LoginResponse.jwt:type_name -> protoManager.JWT
	11, // 4: protoManager.LoginResponse.error:type_name -> protoManager.LoginResponse.Error
	0,  // 5: protoManager.GetNodeResponse.Error.code:type_name -> protoManager.GetNodeResponse.Error.Code
	1,  // 6: protoManager.LoginResponse.Error.code:type_name -> protoManager.LoginResponse.Error.Code
	4,  // 7: protoManager.manager.Registrate:input_type -> protoManager.RegistrateRequest
	5,  // 8: protoManager.manager.GetNode:input_type -> protoManager.GetNodeRequest
	7,  // 9: protoManager.manager.Login:input_type -> protoManager.LoginRequest
	3,  // 10: protoManager.manager.Registrate:output_type -> protoManager.RegistrateResponse
	6,  // 11: protoManager.manager.GetNode:output_type -> protoManager.GetNodeResponse
	8,  // 12: protoManager.manager.Login:output_type -> protoManager.LoginResponse
	10, // [10:13] is the sub-list for method output_type
	7,  // [7:10] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_manager_proto_init() }
func file_manager_proto_init() {
	if File_manager_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_manager_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NodeAgent); i {
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
		file_manager_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegistrateResponse); i {
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
		file_manager_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegistrateRequest); i {
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
		file_manager_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetNodeRequest); i {
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
		file_manager_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetNodeResponse); i {
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
		file_manager_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoginRequest); i {
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
		file_manager_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoginResponse); i {
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
		file_manager_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*JWT); i {
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
		file_manager_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetNodeResponse_Error); i {
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
		file_manager_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoginResponse_Error); i {
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
	file_manager_proto_msgTypes[4].OneofWrappers = []interface{}{
		(*GetNodeResponse_NodeAgent)(nil),
		(*GetNodeResponse_Error_)(nil),
	}
	file_manager_proto_msgTypes[6].OneofWrappers = []interface{}{
		(*LoginResponse_Jwt)(nil),
		(*LoginResponse_Error_)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_manager_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   10,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_manager_proto_goTypes,
		DependencyIndexes: file_manager_proto_depIdxs,
		EnumInfos:         file_manager_proto_enumTypes,
		MessageInfos:      file_manager_proto_msgTypes,
	}.Build()
	File_manager_proto = out.File
	file_manager_proto_rawDesc = nil
	file_manager_proto_goTypes = nil
	file_manager_proto_depIdxs = nil
}
