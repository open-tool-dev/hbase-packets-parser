import json
import socket
import time
from collections import deque
from enum import Enum

import dpkt
import varint
from elasticsearch7 import Elasticsearch

import Client_pb2
import RPC_pb2
from loguru import logger
import argparse

batch_queue = []

total_count = 0


class Step(Enum):
    NONE = 0
    PARSE_CONNECT_HEADER_PREAMBLE = 1
    PARSE_CONNECT_HEADER = 2
    PARSE_REQUEST = 3


class SessionRequests(object):

    def __init__(self, new_conn: bool = False):
        self.new_conn = new_conn
        if new_conn:
            self.step = Step.PARSE_CONNECT_HEADER_PREAMBLE
        else:
            self.step = Step.PARSE_REQUEST
        self.request_packets = bytearray()
        self.response_packets = bytearray()
        self.request_queue = deque[(float, int)]()
        self.response_queue = deque[(float, int)]()
        self.requests = dict[int, HBaseRequest]()


class HBaseRequest(object):

    def __init__(self):
        self.request = dict[str, object]()
        self.response = dict[str, object]()
        self.start_time = 0
        self.end_time = 0


class PacketTime(object):

    def __init__(self, ts: float, size: int):
        self.ts = ts
        self.size = size


def get_lens(bs: bytes):
    if len(bs) != 4:
        raise Exception("bytes size is not 4")
    return bs[0] << 24 | bs[1] << 16 | bs[2] << 8 | bs[3]


def remove_packet_from_queue(queue: deque[PacketTime], size: int, last_packet: bool = False) -> float:
    left = size
    if len(queue) <= 0:
        raise Exception("parse packet error")
    ts = queue[0].ts
    while True:
        if len(queue) <= 0:
            raise Exception("parse packet error")
        item = queue[0]
        if last_packet:
            ts = item.ts
        if item.size > left:
            item.size = item.size - left
            break
        else:
            left = left - item.size
            queue.popleft()
            if left <= 0:
                break
    return ts


def parse_hbase_packet(file: str, port: int, client: Elasticsearch):
    f = open(file, mode="rb")
    packets = dict[str, SessionRequests]()
    pcap = dpkt.pcap.Reader(f)
    for ts, pkt in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            tcp = ip.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            src_port = tcp.sport
            dst_port = tcp.dport
            if dst_port == port:
                key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                if key not in packets or (tcp.flags & dpkt.tcp.TH_SYN) != 0:
                    packets[key] = SessionRequests((tcp.flags & dpkt.tcp.TH_SYN) != 0)
                if len(tcp.data) > 0:
                    packets[key].request_packets.extend(tcp.data)
                    packets[key].request_queue.append(PacketTime(ts, len(tcp.data)))
                    if packets[key].step == Step.PARSE_CONNECT_HEADER_PREAMBLE:
                        if len(packets[key].request_packets) >= 6:
                            packets[key].request_packets = packets[key].request_packets[6:]
                            packets[key].step = Step.PARSE_CONNECT_HEADER
                            remove_packet_from_queue(packets[key].request_queue, 6)
                    elif packets[key].step == Step.PARSE_CONNECT_HEADER:
                        if len(packets[key].request_packets) >= 4:
                            pkt_len = get_lens(bytes(packets[key].request_packets[0:4]))
                            if len(packets[key].request_packets) >= pkt_len + 4:
                                packets[key].request_packets = packets[key].request_packets[4:]
                                pkt_buf = packets[key].request_packets[0:pkt_len]
                                h = RPC_pb2.ConnectionHeader()
                                h.ParseFromString(bytes(pkt_buf))
                                packets[key].request_packets = packets[key].request_packets[pkt_len:]
                                packets[key].step = Step.PARSE_REQUEST
                                remove_packet_from_queue(packets[key].request_queue, pkt_len + 4)
                    elif packets[key].step == Step.PARSE_REQUEST:
                        if len(packets[key].request_packets) >= 4:
                            pkt_len_buf = packets[key].request_packets[0:4]
                            pkt_len = get_lens(bytes(pkt_len_buf))
                            if len(packets[key].request_packets) >= pkt_len + 4:
                                packets[key].request_packets = packets[key].request_packets[4:]
                                header_buf = packets[key].request_packets[0:5] \
                                    if len(packets[key].request_packets) >= 5 else packets[key].request_packets[0:]
                                header_len = varint.decode_bytes(bytes(header_buf))
                                header_len_bytes = len(varint.encode(header_len))
                                packets[key].request_packets = packets[key].request_packets[header_len_bytes:]
                                h = RPC_pb2.RequestHeader()
                                h.ParseFromString(bytes(packets[key].request_packets[0:header_len]))
                                packets[key].request_packets = packets[key].request_packets[header_len:]
                                left_bytes_len = pkt_len - header_len_bytes - header_len
                                request = dict[str, object]()
                                # requests
                                call_id = h.call_id
                                request["method_name"] = h.method_name
                                if h.request_param:
                                    param_buf = packets[key].request_packets[0:5] \
                                        if len(packets[key].request_packets) >= 5 \
                                        else packets[key].request_packets[0:]
                                    param_len = varint.decode_bytes(bytes(param_buf))
                                    param_len_bytes = len(varint.encode(param_len))
                                    packets[key].request_packets = packets[key].request_packets[param_len_bytes:]
                                    try:
                                        m = None
                                        match h.method_name:
                                            case "Scan":
                                                m = Client_pb2.ScanRequest()
                                                m.ParseFromString(bytes(packets[key].request_packets[0:param_len]))
                                            case "Get":
                                                m = Client_pb2.GetRequest()
                                                m.ParseFromString(bytes(packets[key].request_packets[0:param_len]))
                                            case "Multi":
                                                m = Client_pb2.MultiRequest()
                                                m.ParseFromString(bytes(packets[key].request_packets[0:param_len]))
                                        if m:
                                            request["content"] = m
                                    finally:
                                        packets[key].request_packets = packets[key].request_packets[param_len:]
                                    left_bytes_len = left_bytes_len - param_len_bytes - param_len
                                packets[key].request_packets = packets[key].request_packets[left_bytes_len:]
                                fts = remove_packet_from_queue(packets[key].request_queue, pkt_len + 4)
                                hr = HBaseRequest()
                                hr.start_time = fts
                                hr.request = request
                                packets[key].requests[call_id] = hr
            else:
                key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
                if key not in packets or (tcp.flags & dpkt.tcp.TH_SYN) != 0:
                    if key not in packets:
                        packets[key] = SessionRequests((tcp.flags & dpkt.tcp.TH_SYN) != 0)
                if len(tcp.data) > 0:
                    packets[key].response_packets.extend(tcp.data)
                    packets[key].response_queue.append(PacketTime(ts, len(tcp.data)))
                if len(packets[key].response_packets) >= 4:
                    pkt_len_buf = packets[key].response_packets[0:4]
                    pkt_len = get_lens(bytes(pkt_len_buf))
                    if len(packets[key].response_packets) >= pkt_len + 4:
                        packets[key].response_packets = packets[key].response_packets[4:]
                        header_buf = packets[key].response_packets[0:5] \
                            if len(packets[key].response_packets) >= 5 else packets[key].response_packets[0:]
                        header_len = varint.decode_bytes(bytes(header_buf))
                        header_len_bytes = len(varint.encode(header_len))
                        packets[key].response_packets = packets[key].response_packets[header_len_bytes:]
                        h = RPC_pb2.ResponseHeader()
                        h.ParseFromString(bytes(packets[key].response_packets[0:header_len]))
                        packets[key].response_packets = packets[key].response_packets[header_len:]
                        left_bytes_len = pkt_len - header_len_bytes - header_len
                        packets[key].response_packets = packets[key].response_packets[left_bytes_len:]
                        fts = remove_packet_from_queue(packets[key].response_queue, pkt_len + 4)
                        call_id = h.call_id
                        if call_id in packets[key].requests:
                            req = packets[key].requests.get(call_id)
                            req.end_time = fts
                            index_packets_info(
                                client, call_id, req.start_time, req.end_time, req.request,
                                f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"
                            )
                            del packets[key].requests[call_id]
                        else:
                            logger.warning(f"missing request {call_id}, ts={fts} in {key}")
            if (tcp.flags & dpkt.tcp.TH_RST) != 0 or (tcp.flags & dpkt.tcp.TH_FIN) != 0:
                if dst_port == port:
                    key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                else:
                    key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
                for call_id, req in packets[key].requests.items():
                    req.end_time = req.end_time if req.end_time is not None else time.time()
                    index_packets_info(
                        client, call_id, req.start_time, req.end_time, req.request,
                        f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"
                    )
                del packets[key]
        except Exception as e:
            logger.exception(e)
            raise e
    for k, v in packets.items():
        parts = k.split("->")
        for call_id, vi in v.requests.items():
            index_unfinished_packets_info(client, call_id, vi.start_time, vi.request, parts[0], parts[1])
    flush_packets(client)
    logger.info(f"----------- dpkt parse success. result: {total_count}-----------")
    print(f"----------- dpkt parse success. result: {total_count}-----------")


def flush_packets(client: Elasticsearch):
    global total_count
    global batch_queue
    if client is None:
        return
    if len(batch_queue) > 0:
        actions = []
        for doc in batch_queue:
            total_count = total_count + 1
            actions.append({"index": {"_index": "hbase_packets"}})
            actions.append(json.dumps(doc))
        client.bulk(body=actions, index="hbase_packets")
        for action in actions:
            logger.info(f"index action: {action}")
        batch_queue.clear()


def index_unfinished_packets_info(client: Elasticsearch, call_id: int, start_time: float, request: dict,
                                  src_addr: str = None, dest_addr: str = None):
    global batch_queue
    batch_queue.append({
        "@timestamp": int(start_time * 1000),
        "call_id": call_id,
        "src_addr": src_addr.split(":")[0] if src_addr is not None else "",
        "src_port": src_addr.split(":")[1] if src_addr is not None else "",
        "dst_addr": dest_addr.split(":")[0] if dest_addr is not None else "",
        "dst_port": dest_addr.split(":")[1] if dest_addr is not None else "",
        "start_time": int(start_time * 1000),
        "end_time": 0,
        "content": str(request),
        "method": request["method_name"],
        "cost_time_ms": -1
    })
    if len(batch_queue) >= 256:
        flush_packets(client)


def index_packets_info(client: Elasticsearch, call_id: int, start_time: float, end_time: float, request: dict,
                       src_addr: str = None, dest_addr: str = None):
    global batch_queue
    batch_queue.append({
        "@timestamp": int(start_time * 1000),
        "call_id": call_id,
        "src_addr": src_addr.split(":")[0] if src_addr is not None else "",
        "src_port": src_addr.split(":")[1] if src_addr is not None else "",
        "dst_addr": dest_addr.split(":")[0] if dest_addr is not None else "",
        "dst_port": dest_addr.split(":")[1] if dest_addr is not None else "",
        "start_time": int(start_time * 1000),
        "end_time": int(end_time * 1000),
        "content": str(request),
        "method": request["method_name"],
        "cost_time_ms": (end_time - start_time) * 1000
    })
    if len(batch_queue) >= 256:
        flush_packets(client)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", type=str, required=True, help="pcap file")
    parser.add_argument("-log", type=str, required=False, help="log file", default="result.log")
    parser.add_argument("--elastic_host", type=str, required=False, help="elasticsearch host", default="")
    parser.add_argument("--elastic_user", type=str, required=False, help="elasticsearch user", default="")
    parser.add_argument("--elastic_password", type=str, required=False, help="elasticsearch password", default="")
    args = parser.parse_args()
    logger.remove(0)
    logger.add(args.log, rotation="1 hours", encoding="utf-8", backtrace=True,
               format="{time} | {level} | {message}")
    if args.elastic_host:
        elastic_client = None
        hosts = [s.strip() for s in args.elastic_host.split(",")]
        if args.elastic_user and args.elastic_password:
            elastic_client = Elasticsearch(hosts=hosts, http_auth=(args.elastic_user, args.elastic_password))
        else:
            elastic_client = Elasticsearch(hosts=hosts)
        try:
            parse_hbase_packet(args.f, 16020, elastic_client)
        finally:
            elastic_client.close()
