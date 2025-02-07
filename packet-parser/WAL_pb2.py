# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: WAL.proto
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
    'WAL.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import Table_pb2 as Table__pb2
import HBase_pb2 as HBase__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\tWAL.proto\x12\x08hbase.pb\x1a\x0bTable.proto\x1a\x0bHBase.proto\"\x8f\x01\n\tWALHeader\x12\x17\n\x0fhas_compression\x18\x01 \x01(\x08\x12\x16\n\x0e\x65ncryption_key\x18\x02 \x01(\x0c\x12\x1b\n\x13has_tag_compression\x18\x03 \x01(\x08\x12\x17\n\x0fwriter_cls_name\x18\x04 \x01(\t\x12\x1b\n\x13\x63\x65ll_codec_cls_name\x18\x05 \x01(\t\"\xbb\x02\n\x06WALKey\x12\x1b\n\x13\x65ncoded_region_name\x18\x01 \x02(\x0c\x12\x12\n\ntable_name\x18\x02 \x02(\x0c\x12\x1b\n\x13log_sequence_number\x18\x03 \x02(\x04\x12\x12\n\nwrite_time\x18\x04 \x02(\x04\x12&\n\ncluster_id\x18\x05 \x01(\x0b\x32\x0e.hbase.pb.UUIDB\x02\x18\x01\x12%\n\x06scopes\x18\x06 \x03(\x0b\x32\x15.hbase.pb.FamilyScope\x12\x1a\n\x12\x66ollowing_kv_count\x18\x07 \x01(\r\x12#\n\x0b\x63luster_ids\x18\x08 \x03(\x0b\x32\x0e.hbase.pb.UUID\x12\x12\n\nnonceGroup\x18\t \x01(\x04\x12\r\n\x05nonce\x18\n \x01(\x04\x12\x1c\n\x14orig_sequence_number\x18\x0b \x01(\x04\"F\n\x0b\x46\x61milyScope\x12\x0e\n\x06\x66\x61mily\x18\x01 \x02(\x0c\x12\'\n\nscope_type\x18\x02 \x02(\x0e\x32\x13.hbase.pb.ScopeType\"\xbe\x01\n\x14\x43ompactionDescriptor\x12\x12\n\ntable_name\x18\x01 \x02(\x0c\x12\x1b\n\x13\x65ncoded_region_name\x18\x02 \x02(\x0c\x12\x13\n\x0b\x66\x61mily_name\x18\x03 \x02(\x0c\x12\x18\n\x10\x63ompaction_input\x18\x04 \x03(\t\x12\x19\n\x11\x63ompaction_output\x18\x05 \x03(\t\x12\x16\n\x0estore_home_dir\x18\x06 \x02(\t\x12\x13\n\x0bregion_name\x18\x07 \x01(\x0c\"\xa4\x03\n\x0f\x46lushDescriptor\x12\x35\n\x06\x61\x63tion\x18\x01 \x02(\x0e\x32%.hbase.pb.FlushDescriptor.FlushAction\x12\x12\n\ntable_name\x18\x02 \x02(\x0c\x12\x1b\n\x13\x65ncoded_region_name\x18\x03 \x02(\x0c\x12\x1d\n\x15\x66lush_sequence_number\x18\x04 \x01(\x04\x12\x45\n\rstore_flushes\x18\x05 \x03(\x0b\x32..hbase.pb.FlushDescriptor.StoreFlushDescriptor\x12\x13\n\x0bregion_name\x18\x06 \x01(\x0c\x1aY\n\x14StoreFlushDescriptor\x12\x13\n\x0b\x66\x61mily_name\x18\x01 \x02(\x0c\x12\x16\n\x0estore_home_dir\x18\x02 \x02(\t\x12\x14\n\x0c\x66lush_output\x18\x03 \x03(\t\"S\n\x0b\x46lushAction\x12\x0f\n\x0bSTART_FLUSH\x10\x00\x12\x10\n\x0c\x43OMMIT_FLUSH\x10\x01\x12\x0f\n\x0b\x41\x42ORT_FLUSH\x10\x02\x12\x10\n\x0c\x43\x41NNOT_FLUSH\x10\x03\"q\n\x0fStoreDescriptor\x12\x13\n\x0b\x66\x61mily_name\x18\x01 \x02(\x0c\x12\x16\n\x0estore_home_dir\x18\x02 \x02(\t\x12\x12\n\nstore_file\x18\x03 \x03(\t\x12\x1d\n\x15store_file_size_bytes\x18\x04 \x01(\x04\"\x9f\x01\n\x12\x42ulkLoadDescriptor\x12\'\n\ntable_name\x18\x01 \x02(\x0b\x32\x13.hbase.pb.TableName\x12\x1b\n\x13\x65ncoded_region_name\x18\x02 \x02(\x0c\x12)\n\x06stores\x18\x03 \x03(\x0b\x32\x19.hbase.pb.StoreDescriptor\x12\x18\n\x10\x62ulkload_seq_num\x18\x04 \x02(\x03\"\xba\x02\n\x15RegionEventDescriptor\x12=\n\nevent_type\x18\x01 \x02(\x0e\x32).hbase.pb.RegionEventDescriptor.EventType\x12\x12\n\ntable_name\x18\x02 \x02(\x0c\x12\x1b\n\x13\x65ncoded_region_name\x18\x03 \x02(\x0c\x12\x1b\n\x13log_sequence_number\x18\x04 \x01(\x04\x12)\n\x06stores\x18\x05 \x03(\x0b\x32\x19.hbase.pb.StoreDescriptor\x12$\n\x06server\x18\x06 \x01(\x0b\x32\x14.hbase.pb.ServerName\x12\x13\n\x0bregion_name\x18\x07 \x01(\x0c\".\n\tEventType\x12\x0f\n\x0bREGION_OPEN\x10\x00\x12\x10\n\x0cREGION_CLOSE\x10\x01\"\x0c\n\nWALTrailer*F\n\tScopeType\x12\x1b\n\x17REPLICATION_SCOPE_LOCAL\x10\x00\x12\x1c\n\x18REPLICATION_SCOPE_GLOBAL\x10\x01\x42?\n*org.apache.hadoop.hbase.protobuf.generatedB\tWALProtosH\x01\x88\x01\x00\xa0\x01\x01')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'WAL_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n*org.apache.hadoop.hbase.protobuf.generatedB\tWALProtosH\001\210\001\000\240\001\001'
  _globals['_WALKEY'].fields_by_name['cluster_id']._loaded_options = None
  _globals['_WALKEY'].fields_by_name['cluster_id']._serialized_options = b'\030\001'
  _globals['_SCOPETYPE']._serialized_start=1809
  _globals['_SCOPETYPE']._serialized_end=1879
  _globals['_WALHEADER']._serialized_start=50
  _globals['_WALHEADER']._serialized_end=193
  _globals['_WALKEY']._serialized_start=196
  _globals['_WALKEY']._serialized_end=511
  _globals['_FAMILYSCOPE']._serialized_start=513
  _globals['_FAMILYSCOPE']._serialized_end=583
  _globals['_COMPACTIONDESCRIPTOR']._serialized_start=586
  _globals['_COMPACTIONDESCRIPTOR']._serialized_end=776
  _globals['_FLUSHDESCRIPTOR']._serialized_start=779
  _globals['_FLUSHDESCRIPTOR']._serialized_end=1199
  _globals['_FLUSHDESCRIPTOR_STOREFLUSHDESCRIPTOR']._serialized_start=1025
  _globals['_FLUSHDESCRIPTOR_STOREFLUSHDESCRIPTOR']._serialized_end=1114
  _globals['_FLUSHDESCRIPTOR_FLUSHACTION']._serialized_start=1116
  _globals['_FLUSHDESCRIPTOR_FLUSHACTION']._serialized_end=1199
  _globals['_STOREDESCRIPTOR']._serialized_start=1201
  _globals['_STOREDESCRIPTOR']._serialized_end=1314
  _globals['_BULKLOADDESCRIPTOR']._serialized_start=1317
  _globals['_BULKLOADDESCRIPTOR']._serialized_end=1476
  _globals['_REGIONEVENTDESCRIPTOR']._serialized_start=1479
  _globals['_REGIONEVENTDESCRIPTOR']._serialized_end=1793
  _globals['_REGIONEVENTDESCRIPTOR_EVENTTYPE']._serialized_start=1747
  _globals['_REGIONEVENTDESCRIPTOR_EVENTTYPE']._serialized_end=1793
  _globals['_WALTRAILER']._serialized_start=1795
  _globals['_WALTRAILER']._serialized_end=1807
# @@protoc_insertion_point(module_scope)
