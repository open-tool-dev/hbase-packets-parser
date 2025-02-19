# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: AccessControl.proto
# Protobuf Python Version: 5.27.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    27,
    2,
    '',
    'AccessControl.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import Table_pb2 as Table__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13\x41\x63\x63\x65ssControl.proto\x12\x08hbase.pb\x1a\x0bTable.proto\"\xcc\x02\n\nPermission\x12\'\n\x04type\x18\x01 \x02(\x0e\x32\x19.hbase.pb.Permission.Type\x12\x35\n\x11global_permission\x18\x02 \x01(\x0b\x32\x1a.hbase.pb.GlobalPermission\x12;\n\x14namespace_permission\x18\x03 \x01(\x0b\x32\x1d.hbase.pb.NamespacePermission\x12\x33\n\x10table_permission\x18\x04 \x01(\x0b\x32\x19.hbase.pb.TablePermission\">\n\x06\x41\x63tion\x12\x08\n\x04READ\x10\x00\x12\t\n\x05WRITE\x10\x01\x12\x08\n\x04\x45XEC\x10\x02\x12\n\n\x06\x43REATE\x10\x03\x12\t\n\x05\x41\x44MIN\x10\x04\",\n\x04Type\x12\n\n\x06Global\x10\x01\x12\r\n\tNamespace\x10\x02\x12\t\n\x05Table\x10\x03\"\x8a\x01\n\x0fTablePermission\x12\'\n\ntable_name\x18\x01 \x01(\x0b\x32\x13.hbase.pb.TableName\x12\x0e\n\x06\x66\x61mily\x18\x02 \x01(\x0c\x12\x11\n\tqualifier\x18\x03 \x01(\x0c\x12+\n\x06\x61\x63tion\x18\x04 \x03(\x0e\x32\x1b.hbase.pb.Permission.Action\"Z\n\x13NamespacePermission\x12\x16\n\x0enamespace_name\x18\x01 \x01(\x0c\x12+\n\x06\x61\x63tion\x18\x02 \x03(\x0e\x32\x1b.hbase.pb.Permission.Action\"?\n\x10GlobalPermission\x12+\n\x06\x61\x63tion\x18\x01 \x03(\x0e\x32\x1b.hbase.pb.Permission.Action\"H\n\x0eUserPermission\x12\x0c\n\x04user\x18\x01 \x02(\x0c\x12(\n\npermission\x18\x03 \x02(\x0b\x32\x14.hbase.pb.Permission\"\xaa\x01\n\x13UsersAndPermissions\x12G\n\x10user_permissions\x18\x01 \x03(\x0b\x32-.hbase.pb.UsersAndPermissions.UserPermissions\x1aJ\n\x0fUserPermissions\x12\x0c\n\x04user\x18\x01 \x02(\x0c\x12)\n\x0bpermissions\x18\x02 \x03(\x0b\x32\x14.hbase.pb.Permission\"l\n\x0cGrantRequest\x12\x31\n\x0fuser_permission\x18\x01 \x02(\x0b\x32\x18.hbase.pb.UserPermission\x12)\n\x1amerge_existing_permissions\x18\x02 \x01(\x08:\x05\x66\x61lse\"\x0f\n\rGrantResponse\"B\n\rRevokeRequest\x12\x31\n\x0fuser_permission\x18\x01 \x02(\x0b\x32\x18.hbase.pb.UserPermission\"\x10\n\x0eRevokeResponse\"\xc9\x01\n\x19GetUserPermissionsRequest\x12\'\n\x04type\x18\x01 \x01(\x0e\x32\x19.hbase.pb.Permission.Type\x12\'\n\ntable_name\x18\x02 \x01(\x0b\x32\x13.hbase.pb.TableName\x12\x16\n\x0enamespace_name\x18\x03 \x01(\x0c\x12\x15\n\rcolumn_family\x18\x04 \x01(\x0c\x12\x18\n\x10\x63olumn_qualifier\x18\x05 \x01(\x0c\x12\x11\n\tuser_name\x18\x06 \x01(\x0c\"O\n\x1aGetUserPermissionsResponse\x12\x31\n\x0fuser_permission\x18\x01 \x03(\x0b\x32\x18.hbase.pb.UserPermission\"C\n\x17\x43heckPermissionsRequest\x12(\n\npermission\x18\x01 \x03(\x0b\x32\x14.hbase.pb.Permission\"\x1a\n\x18\x43heckPermissionsResponse\"^\n\x14HasPermissionRequest\x12\x33\n\x10table_permission\x18\x01 \x02(\x0b\x32\x19.hbase.pb.TablePermission\x12\x11\n\tuser_name\x18\x02 \x02(\x0c\"/\n\x15HasPermissionResponse\x12\x16\n\x0ehas_permission\x18\x01 \x01(\x08\x32\x9b\x03\n\x14\x41\x63\x63\x65ssControlService\x12\x38\n\x05Grant\x12\x16.hbase.pb.GrantRequest\x1a\x17.hbase.pb.GrantResponse\x12;\n\x06Revoke\x12\x17.hbase.pb.RevokeRequest\x1a\x18.hbase.pb.RevokeResponse\x12_\n\x12GetUserPermissions\x12#.hbase.pb.GetUserPermissionsRequest\x1a$.hbase.pb.GetUserPermissionsResponse\x12Y\n\x10\x43heckPermissions\x12!.hbase.pb.CheckPermissionsRequest\x1a\".hbase.pb.CheckPermissionsResponse\x12P\n\rHasPermission\x12\x1e.hbase.pb.HasPermissionRequest\x1a\x1f.hbase.pb.HasPermissionResponseBI\n*org.apache.hadoop.hbase.protobuf.generatedB\x13\x41\x63\x63\x65ssControlProtosH\x01\x88\x01\x01\xa0\x01\x01')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'AccessControl_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n*org.apache.hadoop.hbase.protobuf.generatedB\023AccessControlProtosH\001\210\001\001\240\001\001'
  _globals['_PERMISSION']._serialized_start=47
  _globals['_PERMISSION']._serialized_end=379
  _globals['_PERMISSION_ACTION']._serialized_start=271
  _globals['_PERMISSION_ACTION']._serialized_end=333
  _globals['_PERMISSION_TYPE']._serialized_start=335
  _globals['_PERMISSION_TYPE']._serialized_end=379
  _globals['_TABLEPERMISSION']._serialized_start=382
  _globals['_TABLEPERMISSION']._serialized_end=520
  _globals['_NAMESPACEPERMISSION']._serialized_start=522
  _globals['_NAMESPACEPERMISSION']._serialized_end=612
  _globals['_GLOBALPERMISSION']._serialized_start=614
  _globals['_GLOBALPERMISSION']._serialized_end=677
  _globals['_USERPERMISSION']._serialized_start=679
  _globals['_USERPERMISSION']._serialized_end=751
  _globals['_USERSANDPERMISSIONS']._serialized_start=754
  _globals['_USERSANDPERMISSIONS']._serialized_end=924
  _globals['_USERSANDPERMISSIONS_USERPERMISSIONS']._serialized_start=850
  _globals['_USERSANDPERMISSIONS_USERPERMISSIONS']._serialized_end=924
  _globals['_GRANTREQUEST']._serialized_start=926
  _globals['_GRANTREQUEST']._serialized_end=1034
  _globals['_GRANTRESPONSE']._serialized_start=1036
  _globals['_GRANTRESPONSE']._serialized_end=1051
  _globals['_REVOKEREQUEST']._serialized_start=1053
  _globals['_REVOKEREQUEST']._serialized_end=1119
  _globals['_REVOKERESPONSE']._serialized_start=1121
  _globals['_REVOKERESPONSE']._serialized_end=1137
  _globals['_GETUSERPERMISSIONSREQUEST']._serialized_start=1140
  _globals['_GETUSERPERMISSIONSREQUEST']._serialized_end=1341
  _globals['_GETUSERPERMISSIONSRESPONSE']._serialized_start=1343
  _globals['_GETUSERPERMISSIONSRESPONSE']._serialized_end=1422
  _globals['_CHECKPERMISSIONSREQUEST']._serialized_start=1424
  _globals['_CHECKPERMISSIONSREQUEST']._serialized_end=1491
  _globals['_CHECKPERMISSIONSRESPONSE']._serialized_start=1493
  _globals['_CHECKPERMISSIONSRESPONSE']._serialized_end=1519
  _globals['_HASPERMISSIONREQUEST']._serialized_start=1521
  _globals['_HASPERMISSIONREQUEST']._serialized_end=1615
  _globals['_HASPERMISSIONRESPONSE']._serialized_start=1617
  _globals['_HASPERMISSIONRESPONSE']._serialized_end=1664
  _globals['_ACCESSCONTROLSERVICE']._serialized_start=1667
  _globals['_ACCESSCONTROLSERVICE']._serialized_end=2078
# @@protoc_insertion_point(module_scope)
