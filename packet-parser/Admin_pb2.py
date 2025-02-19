# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: Admin.proto
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
    'Admin.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import HBase_pb2 as HBase__pb2
import WAL_pb2 as WAL__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0b\x41\x64min.proto\x12\x08hbase.pb\x1a\x0bHBase.proto\x1a\tWAL.proto\"[\n\x14GetRegionInfoRequest\x12)\n\x06region\x18\x01 \x02(\x0b\x32\x19.hbase.pb.RegionSpecifier\x12\x18\n\x10\x63ompaction_state\x18\x02 \x01(\x08\"\xd5\x01\n\x15GetRegionInfoResponse\x12)\n\x0bregion_info\x18\x01 \x02(\x0b\x32\x14.hbase.pb.RegionInfo\x12I\n\x10\x63ompaction_state\x18\x02 \x01(\x0e\x32/.hbase.pb.GetRegionInfoResponse.CompactionState\"F\n\x0f\x43ompactionState\x12\x08\n\x04NONE\x10\x00\x12\t\n\x05MINOR\x10\x01\x12\t\n\x05MAJOR\x10\x02\x12\x13\n\x0fMAJOR_AND_MINOR\x10\x03\"P\n\x13GetStoreFileRequest\x12)\n\x06region\x18\x01 \x02(\x0b\x32\x19.hbase.pb.RegionSpecifier\x12\x0e\n\x06\x66\x61mily\x18\x02 \x03(\x0c\"*\n\x14GetStoreFileResponse\x12\x12\n\nstore_file\x18\x01 \x03(\t\"\x18\n\x16GetOnlineRegionRequest\"D\n\x17GetOnlineRegionResponse\x12)\n\x0bregion_info\x18\x01 \x03(\x0b\x32\x14.hbase.pb.RegionInfo\"\x8e\x02\n\x11OpenRegionRequest\x12=\n\topen_info\x18\x01 \x03(\x0b\x32*.hbase.pb.OpenRegionRequest.RegionOpenInfo\x12\x17\n\x0fserverStartCode\x18\x02 \x01(\x04\x12\x1a\n\x12master_system_time\x18\x05 \x01(\x04\x1a\x84\x01\n\x0eRegionOpenInfo\x12$\n\x06region\x18\x01 \x02(\x0b\x32\x14.hbase.pb.RegionInfo\x12\x1f\n\x17version_of_offline_node\x18\x02 \x01(\r\x12+\n\rfavored_nodes\x18\x03 \x03(\x0b\x32\x14.hbase.pb.ServerName\"\xa6\x01\n\x12OpenRegionResponse\x12\x46\n\ropening_state\x18\x01 \x03(\x0e\x32/.hbase.pb.OpenRegionResponse.RegionOpeningState\"H\n\x12RegionOpeningState\x12\n\n\x06OPENED\x10\x00\x12\x12\n\x0e\x41LREADY_OPENED\x10\x01\x12\x12\n\x0e\x46\x41ILED_OPENING\x10\x02\"?\n\x13WarmupRegionRequest\x12(\n\nregionInfo\x18\x01 \x02(\x0b\x32\x14.hbase.pb.RegionInfo\"\x16\n\x14WarmupRegionResponse\"\xcb\x01\n\x12\x43loseRegionRequest\x12)\n\x06region\x18\x01 \x02(\x0b\x32\x19.hbase.pb.RegionSpecifier\x12\x1f\n\x17version_of_closing_node\x18\x02 \x01(\r\x12\x1e\n\x10transition_in_ZK\x18\x03 \x01(\x08:\x04true\x12\x30\n\x12\x64\x65stination_server\x18\x04 \x01(\x0b\x32\x14.hbase.pb.ServerName\x12\x17\n\x0fserverStartCode\x18\x05 \x01(\x04\"%\n\x13\x43loseRegionResponse\x12\x0e\n\x06\x63losed\x18\x01 \x02(\x08\"y\n\x12\x46lushRegionRequest\x12)\n\x06region\x18\x01 \x02(\x0b\x32\x19.hbase.pb.RegionSpecifier\x12\x18\n\x10if_older_than_ts\x18\x02 \x01(\x04\x12\x1e\n\x16write_flush_wal_marker\x18\x03 \x01(\x08\"_\n\x13\x46lushRegionResponse\x12\x17\n\x0flast_flush_time\x18\x01 \x02(\x04\x12\x0f\n\x07\x66lushed\x18\x02 \x01(\x08\x12\x1e\n\x16wrote_flush_wal_marker\x18\x03 \x01(\x08\"T\n\x12SplitRegionRequest\x12)\n\x06region\x18\x01 \x02(\x0b\x32\x19.hbase.pb.RegionSpecifier\x12\x13\n\x0bsplit_point\x18\x02 \x01(\x0c\"\x15\n\x13SplitRegionResponse\"`\n\x14\x43ompactRegionRequest\x12)\n\x06region\x18\x01 \x02(\x0b\x32\x19.hbase.pb.RegionSpecifier\x12\r\n\x05major\x18\x02 \x01(\x08\x12\x0e\n\x06\x66\x61mily\x18\x03 \x01(\x0c\"\x17\n\x15\x43ompactRegionResponse\"\xcd\x01\n\x19UpdateFavoredNodesRequest\x12I\n\x0bupdate_info\x18\x01 \x03(\x0b\x32\x34.hbase.pb.UpdateFavoredNodesRequest.RegionUpdateInfo\x1a\x65\n\x10RegionUpdateInfo\x12$\n\x06region\x18\x01 \x02(\x0b\x32\x14.hbase.pb.RegionInfo\x12+\n\rfavored_nodes\x18\x02 \x03(\x0b\x32\x14.hbase.pb.ServerName\".\n\x1aUpdateFavoredNodesResponse\x12\x10\n\x08response\x18\x01 \x01(\r\"\xa4\x01\n\x13MergeRegionsRequest\x12+\n\x08region_a\x18\x01 \x02(\x0b\x32\x19.hbase.pb.RegionSpecifier\x12+\n\x08region_b\x18\x02 \x02(\x0b\x32\x19.hbase.pb.RegionSpecifier\x12\x17\n\x08\x66orcible\x18\x03 \x01(\x08:\x05\x66\x61lse\x12\x1a\n\x12master_system_time\x18\x04 \x01(\x04\"\x16\n\x14MergeRegionsResponse\"a\n\x08WALEntry\x12\x1d\n\x03key\x18\x01 \x02(\x0b\x32\x10.hbase.pb.WALKey\x12\x17\n\x0fkey_value_bytes\x18\x02 \x03(\x0c\x12\x1d\n\x15\x61ssociated_cell_count\x18\x03 \x01(\x05\"\xa2\x01\n\x18ReplicateWALEntryRequest\x12!\n\x05\x65ntry\x18\x01 \x03(\x0b\x32\x12.hbase.pb.WALEntry\x12\x1c\n\x14replicationClusterId\x18\x02 \x01(\t\x12\"\n\x1asourceBaseNamespaceDirPath\x18\x03 \x01(\t\x12!\n\x19sourceHFileArchiveDirPath\x18\x04 \x01(\t\"\x1b\n\x19ReplicateWALEntryResponse\"\x16\n\x14RollWALWriterRequest\"0\n\x15RollWALWriterResponse\x12\x17\n\x0fregion_to_flush\x18\x01 \x03(\x0c\"#\n\x11StopServerRequest\x12\x0e\n\x06reason\x18\x01 \x02(\t\"\x14\n\x12StopServerResponse\"\x16\n\x14GetServerInfoRequest\"K\n\nServerInfo\x12)\n\x0bserver_name\x18\x01 \x02(\x0b\x32\x14.hbase.pb.ServerName\x12\x12\n\nwebui_port\x18\x02 \x01(\r\"B\n\x15GetServerInfoResponse\x12)\n\x0bserver_info\x18\x01 \x02(\x0b\x32\x14.hbase.pb.ServerInfo\"\x1c\n\x1aUpdateConfigurationRequest\"\x1d\n\x1bUpdateConfigurationResponse2\x87\x0b\n\x0c\x41\x64minService\x12P\n\rGetRegionInfo\x12\x1e.hbase.pb.GetRegionInfoRequest\x1a\x1f.hbase.pb.GetRegionInfoResponse\x12M\n\x0cGetStoreFile\x12\x1d.hbase.pb.GetStoreFileRequest\x1a\x1e.hbase.pb.GetStoreFileResponse\x12V\n\x0fGetOnlineRegion\x12 .hbase.pb.GetOnlineRegionRequest\x1a!.hbase.pb.GetOnlineRegionResponse\x12G\n\nOpenRegion\x12\x1b.hbase.pb.OpenRegionRequest\x1a\x1c.hbase.pb.OpenRegionResponse\x12M\n\x0cWarmupRegion\x12\x1d.hbase.pb.WarmupRegionRequest\x1a\x1e.hbase.pb.WarmupRegionResponse\x12J\n\x0b\x43loseRegion\x12\x1c.hbase.pb.CloseRegionRequest\x1a\x1d.hbase.pb.CloseRegionResponse\x12J\n\x0b\x46lushRegion\x12\x1c.hbase.pb.FlushRegionRequest\x1a\x1d.hbase.pb.FlushRegionResponse\x12J\n\x0bSplitRegion\x12\x1c.hbase.pb.SplitRegionRequest\x1a\x1d.hbase.pb.SplitRegionResponse\x12P\n\rCompactRegion\x12\x1e.hbase.pb.CompactRegionRequest\x1a\x1f.hbase.pb.CompactRegionResponse\x12M\n\x0cMergeRegions\x12\x1d.hbase.pb.MergeRegionsRequest\x1a\x1e.hbase.pb.MergeRegionsResponse\x12\\\n\x11ReplicateWALEntry\x12\".hbase.pb.ReplicateWALEntryRequest\x1a#.hbase.pb.ReplicateWALEntryResponse\x12Q\n\x06Replay\x12\".hbase.pb.ReplicateWALEntryRequest\x1a#.hbase.pb.ReplicateWALEntryResponse\x12P\n\rRollWALWriter\x12\x1e.hbase.pb.RollWALWriterRequest\x1a\x1f.hbase.pb.RollWALWriterResponse\x12P\n\rGetServerInfo\x12\x1e.hbase.pb.GetServerInfoRequest\x1a\x1f.hbase.pb.GetServerInfoResponse\x12G\n\nStopServer\x12\x1b.hbase.pb.StopServerRequest\x1a\x1c.hbase.pb.StopServerResponse\x12_\n\x12UpdateFavoredNodes\x12#.hbase.pb.UpdateFavoredNodesRequest\x1a$.hbase.pb.UpdateFavoredNodesResponse\x12\x62\n\x13UpdateConfiguration\x12$.hbase.pb.UpdateConfigurationRequest\x1a%.hbase.pb.UpdateConfigurationResponseBA\n*org.apache.hadoop.hbase.protobuf.generatedB\x0b\x41\x64minProtosH\x01\x88\x01\x01\xa0\x01\x01')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'Admin_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n*org.apache.hadoop.hbase.protobuf.generatedB\013AdminProtosH\001\210\001\001\240\001\001'
  _globals['_GETREGIONINFOREQUEST']._serialized_start=49
  _globals['_GETREGIONINFOREQUEST']._serialized_end=140
  _globals['_GETREGIONINFORESPONSE']._serialized_start=143
  _globals['_GETREGIONINFORESPONSE']._serialized_end=356
  _globals['_GETREGIONINFORESPONSE_COMPACTIONSTATE']._serialized_start=286
  _globals['_GETREGIONINFORESPONSE_COMPACTIONSTATE']._serialized_end=356
  _globals['_GETSTOREFILEREQUEST']._serialized_start=358
  _globals['_GETSTOREFILEREQUEST']._serialized_end=438
  _globals['_GETSTOREFILERESPONSE']._serialized_start=440
  _globals['_GETSTOREFILERESPONSE']._serialized_end=482
  _globals['_GETONLINEREGIONREQUEST']._serialized_start=484
  _globals['_GETONLINEREGIONREQUEST']._serialized_end=508
  _globals['_GETONLINEREGIONRESPONSE']._serialized_start=510
  _globals['_GETONLINEREGIONRESPONSE']._serialized_end=578
  _globals['_OPENREGIONREQUEST']._serialized_start=581
  _globals['_OPENREGIONREQUEST']._serialized_end=851
  _globals['_OPENREGIONREQUEST_REGIONOPENINFO']._serialized_start=719
  _globals['_OPENREGIONREQUEST_REGIONOPENINFO']._serialized_end=851
  _globals['_OPENREGIONRESPONSE']._serialized_start=854
  _globals['_OPENREGIONRESPONSE']._serialized_end=1020
  _globals['_OPENREGIONRESPONSE_REGIONOPENINGSTATE']._serialized_start=948
  _globals['_OPENREGIONRESPONSE_REGIONOPENINGSTATE']._serialized_end=1020
  _globals['_WARMUPREGIONREQUEST']._serialized_start=1022
  _globals['_WARMUPREGIONREQUEST']._serialized_end=1085
  _globals['_WARMUPREGIONRESPONSE']._serialized_start=1087
  _globals['_WARMUPREGIONRESPONSE']._serialized_end=1109
  _globals['_CLOSEREGIONREQUEST']._serialized_start=1112
  _globals['_CLOSEREGIONREQUEST']._serialized_end=1315
  _globals['_CLOSEREGIONRESPONSE']._serialized_start=1317
  _globals['_CLOSEREGIONRESPONSE']._serialized_end=1354
  _globals['_FLUSHREGIONREQUEST']._serialized_start=1356
  _globals['_FLUSHREGIONREQUEST']._serialized_end=1477
  _globals['_FLUSHREGIONRESPONSE']._serialized_start=1479
  _globals['_FLUSHREGIONRESPONSE']._serialized_end=1574
  _globals['_SPLITREGIONREQUEST']._serialized_start=1576
  _globals['_SPLITREGIONREQUEST']._serialized_end=1660
  _globals['_SPLITREGIONRESPONSE']._serialized_start=1662
  _globals['_SPLITREGIONRESPONSE']._serialized_end=1683
  _globals['_COMPACTREGIONREQUEST']._serialized_start=1685
  _globals['_COMPACTREGIONREQUEST']._serialized_end=1781
  _globals['_COMPACTREGIONRESPONSE']._serialized_start=1783
  _globals['_COMPACTREGIONRESPONSE']._serialized_end=1806
  _globals['_UPDATEFAVOREDNODESREQUEST']._serialized_start=1809
  _globals['_UPDATEFAVOREDNODESREQUEST']._serialized_end=2014
  _globals['_UPDATEFAVOREDNODESREQUEST_REGIONUPDATEINFO']._serialized_start=1913
  _globals['_UPDATEFAVOREDNODESREQUEST_REGIONUPDATEINFO']._serialized_end=2014
  _globals['_UPDATEFAVOREDNODESRESPONSE']._serialized_start=2016
  _globals['_UPDATEFAVOREDNODESRESPONSE']._serialized_end=2062
  _globals['_MERGEREGIONSREQUEST']._serialized_start=2065
  _globals['_MERGEREGIONSREQUEST']._serialized_end=2229
  _globals['_MERGEREGIONSRESPONSE']._serialized_start=2231
  _globals['_MERGEREGIONSRESPONSE']._serialized_end=2253
  _globals['_WALENTRY']._serialized_start=2255
  _globals['_WALENTRY']._serialized_end=2352
  _globals['_REPLICATEWALENTRYREQUEST']._serialized_start=2355
  _globals['_REPLICATEWALENTRYREQUEST']._serialized_end=2517
  _globals['_REPLICATEWALENTRYRESPONSE']._serialized_start=2519
  _globals['_REPLICATEWALENTRYRESPONSE']._serialized_end=2546
  _globals['_ROLLWALWRITERREQUEST']._serialized_start=2548
  _globals['_ROLLWALWRITERREQUEST']._serialized_end=2570
  _globals['_ROLLWALWRITERRESPONSE']._serialized_start=2572
  _globals['_ROLLWALWRITERRESPONSE']._serialized_end=2620
  _globals['_STOPSERVERREQUEST']._serialized_start=2622
  _globals['_STOPSERVERREQUEST']._serialized_end=2657
  _globals['_STOPSERVERRESPONSE']._serialized_start=2659
  _globals['_STOPSERVERRESPONSE']._serialized_end=2679
  _globals['_GETSERVERINFOREQUEST']._serialized_start=2681
  _globals['_GETSERVERINFOREQUEST']._serialized_end=2703
  _globals['_SERVERINFO']._serialized_start=2705
  _globals['_SERVERINFO']._serialized_end=2780
  _globals['_GETSERVERINFORESPONSE']._serialized_start=2782
  _globals['_GETSERVERINFORESPONSE']._serialized_end=2848
  _globals['_UPDATECONFIGURATIONREQUEST']._serialized_start=2850
  _globals['_UPDATECONFIGURATIONREQUEST']._serialized_end=2878
  _globals['_UPDATECONFIGURATIONRESPONSE']._serialized_start=2880
  _globals['_UPDATECONFIGURATIONRESPONSE']._serialized_end=2909
  _globals['_ADMINSERVICE']._serialized_start=2912
  _globals['_ADMINSERVICE']._serialized_end=4327
# @@protoc_insertion_point(module_scope)
