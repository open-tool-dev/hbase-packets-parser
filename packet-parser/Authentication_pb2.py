# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: Authentication.proto
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
    'Authentication.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x14\x41uthentication.proto\x12\x08hbase.pb\"E\n\x11\x41uthenticationKey\x12\n\n\x02id\x18\x01 \x02(\x05\x12\x17\n\x0f\x65xpiration_date\x18\x02 \x02(\x03\x12\x0b\n\x03key\x18\x03 \x02(\x0c\"\xc5\x01\n\x0fTokenIdentifier\x12,\n\x04kind\x18\x01 \x02(\x0e\x32\x1e.hbase.pb.TokenIdentifier.Kind\x12\x10\n\x08username\x18\x02 \x02(\x0c\x12\x0e\n\x06key_id\x18\x03 \x02(\x05\x12\x12\n\nissue_date\x18\x04 \x01(\x03\x12\x17\n\x0f\x65xpiration_date\x18\x05 \x01(\x03\x12\x17\n\x0fsequence_number\x18\x06 \x01(\x03\"\x1c\n\x04Kind\x12\x14\n\x10HBASE_AUTH_TOKEN\x10\x00\">\n\x05Token\x12\x12\n\nidentifier\x18\x01 \x01(\x0c\x12\x10\n\x08password\x18\x02 \x01(\x0c\x12\x0f\n\x07service\x18\x03 \x01(\x0c\"\x1f\n\x1dGetAuthenticationTokenRequest\"@\n\x1eGetAuthenticationTokenResponse\x12\x1e\n\x05token\x18\x01 \x01(\x0b\x32\x0f.hbase.pb.Token\"\x0f\n\rWhoAmIRequest\"7\n\x0eWhoAmIResponse\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x13\n\x0b\x61uth_method\x18\x02 \x01(\t2\xc1\x01\n\x15\x41uthenticationService\x12k\n\x16GetAuthenticationToken\x12\'.hbase.pb.GetAuthenticationTokenRequest\x1a(.hbase.pb.GetAuthenticationTokenResponse\x12;\n\x06WhoAmI\x12\x17.hbase.pb.WhoAmIRequest\x1a\x18.hbase.pb.WhoAmIResponseBJ\n*org.apache.hadoop.hbase.protobuf.generatedB\x14\x41uthenticationProtosH\x01\x88\x01\x01\xa0\x01\x01')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'Authentication_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n*org.apache.hadoop.hbase.protobuf.generatedB\024AuthenticationProtosH\001\210\001\001\240\001\001'
  _globals['_AUTHENTICATIONKEY']._serialized_start=34
  _globals['_AUTHENTICATIONKEY']._serialized_end=103
  _globals['_TOKENIDENTIFIER']._serialized_start=106
  _globals['_TOKENIDENTIFIER']._serialized_end=303
  _globals['_TOKENIDENTIFIER_KIND']._serialized_start=275
  _globals['_TOKENIDENTIFIER_KIND']._serialized_end=303
  _globals['_TOKEN']._serialized_start=305
  _globals['_TOKEN']._serialized_end=367
  _globals['_GETAUTHENTICATIONTOKENREQUEST']._serialized_start=369
  _globals['_GETAUTHENTICATIONTOKENREQUEST']._serialized_end=400
  _globals['_GETAUTHENTICATIONTOKENRESPONSE']._serialized_start=402
  _globals['_GETAUTHENTICATIONTOKENRESPONSE']._serialized_end=466
  _globals['_WHOAMIREQUEST']._serialized_start=468
  _globals['_WHOAMIREQUEST']._serialized_end=483
  _globals['_WHOAMIRESPONSE']._serialized_start=485
  _globals['_WHOAMIRESPONSE']._serialized_end=540
  _globals['_AUTHENTICATIONSERVICE']._serialized_start=543
  _globals['_AUTHENTICATIONSERVICE']._serialized_end=736
# @@protoc_insertion_point(module_scope)
