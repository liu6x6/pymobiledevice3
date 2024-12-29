import logging
import asyncio
from pprint import pformat
from typing import List, MutableMapping, Optional

import click
import coloredlogs
from construct import ConstError, StreamError
from hexdump import hexdump
from hyperframe.frame import DataFrame, Frame, GoAwayFrame, HeadersFrame
from scapy.layers.inet import IP, TCP,UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from scapy.sendrecv import sniff
from scapy.all import get_if_list, get_working_if, show_interfaces

from pymobiledevice3.remote.tunnel_service import PairingDataComponentTLVBuf
from pymobiledevice3.remote.remotexpc import HTTP2_MAGIC
from pymobiledevice3.remote.xpc_message import XpcWrapper, decode_xpc_object
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.parse_xpc_header import ParseDTXHelper
from pymobiledevice3.ParsePlistHelper import ParsePlistHelper

import time
from datetime import datetime 
import pickle
import subprocess
import sys
import os
import shutil
import requests
import psutil
import socket

BPLIST_MAGIC = b'bplist'
PLIST_MAGIC = b'<plist'
import plistlib
import pprint
import xml
from typing import IO, Optional

import click
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff



def get_interface_name(base_ipv6_address: str):
    target_ipv6_address = base_ipv6_address[:-1] + '2' 
    for interface_name, interface_addresses in psutil.net_if_addrs().items():
        for address in interface_addresses:
            # print(address.address  + "" + interface_name)
            # if address.family == socket.AF_INET6:  # Filter for IPv6 addresses
            if address.address == target_ipv6_address:
                print(f"Interface: {interface_name} has matching address: {target_ipv6_address}")
                return interface_name
    print("could not find ip = " + target_ipv6_address)
    return ""                


TUNNELD_DEFAULT_ADDRESS = ('127.0.0.1', 49151)
# we could get the tunnel address add port
# from http://127.0.0.1:49151/
def get_py3_rsd():
    resp = requests.get(f'http://{TUNNELD_DEFAULT_ADDRESS[0]}:{TUNNELD_DEFAULT_ADDRESS[1]}')
    parsed_data = resp.json()
    device_key, tunnel_info_list = next(iter(parsed_data.items()))
    tunnel_info = tunnel_info_list[0]
    # Extract the tunnel address and tunnel port
    tunnel_address = tunnel_info['tunnel-address']
    tunnel_port = tunnel_info['tunnel-port']
    return device_key,tunnel_address,tunnel_port


def get_go_rsd(): 
    resp = requests.get(f'http://127.0.0.1:60105/tunnels')
    parsed_data = resp.json()
    tunnel_info = parsed_data[0]
    uuid =  tunnel_info['udid']
    tunnel_address = tunnel_info['address']
    tunnel_port = tunnel_info['rsdPort']
    return uuid, tunnel_address, tunnel_port

# device_udid,address,rsd_port = get_go_rsd()
device_udid,address,rsd_port = get_go_rsd()

interface_name = get_interface_name(address)

interface = interface_name

print(address)
print(rsd_port)
print(interface)

logger = logging.getLogger()

coloredlogs.install(level=logging.DEBUG)

FRAME_HEADER_SIZE = 9
Debug_Folder = "/Users/xiao"

Packets_Folder = "{}/packets".format(Debug_Folder)
if not os.path.exists(Packets_Folder):
    os.makedirs(Packets_Folder)

interface_folder = '{}/{}'.format(Packets_Folder, interface)
if not os.path.exists(interface_folder):
    os.makedirs(interface_folder)

for filename in os.listdir(interface_folder):
    file_path = os.path.join(interface_folder, filename)
    try:
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path)
    except Exception as e:
        print('Failed to delete %s. Reason: %s' % (file_path, e))

xcruntest_data = b''
fileIndex = 0
singleIndex = 0
xpcWrapperIndex = 0
packet_id = 0

# pickle_file_path = '{}/{}_{}.pickle'.format(Debug_Folder,address.replace(":",""), rsd_port)
# if not os.path.isfile(pickle_file_path):
    # raise Exception("Please prepare rsd info in {} first".format(pickle_file_path))
    # with RemoteServiceDiscoveryService((address, rsd_port)) as rsd:
    #     # change mode to read and write for pickle_file_path
    #     os.chmod(pickle_file_path, 0o777)
    #     print(rsd)

peer_info = {}
rsd = RemoteServiceDiscoveryService((address,rsd_port))
asyncio.run(rsd.connect())
time.sleep(1)
peer_info = rsd.peer_info

services = {str(rsd_port): "RSD"}

for service_name, service_data in peer_info["Services"].items():
    if 'Port' in service_data:
        services[str(service_data['Port'])] = service_name[10:]
print(services)
def create_stream_key(src: str, sport: int, dst: str, dport: int) -> str:
    return f'{src}/{sport} ==> {dst}/{dport}'


class TCPStream:
    def __init__(self, src: str, sport: int, dst: str, dport: int):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.key = create_stream_key(src, sport, dst, dport)
        self.data = bytearray()
        self.seq: Optional[int] = None  # so we know seq hasn't been initialized yet
        self.segments = {}  # data segments to add later

    def __repr__(self) -> str:
        return f'Stream<{self.key}>'

    def __len__(self) -> int:
        return len(self.data)

    def add(self, tcp_pkt: TCP, inbound:bool=False) -> bool:
        """
        Returns True if we added an in-order segment, False if not
        """
        if self.seq is None:
            # set initial seq
            self.seq = tcp_pkt.seq
        data = bytes(tcp_pkt.payload)
        data_len = len(data)
        seq_offset = tcp_pkt.seq - self.seq
        if len(self.data) < seq_offset:
            # if this data is out of order and needs to be inserted later
            self.segments[seq_offset] = data
            return False
        else:
            # if this data is in order (has a place to be inserted)
            self.data[seq_offset:seq_offset + data_len] = data
            # check if there are any waiting data segments to add
            for seq_offset in sorted(self.segments.keys()):
                if seq_offset <= len(self.data):  # if we can add this segment to the stream
                    segment_payload = self.segments[seq_offset]
                    self.data[seq_offset:seq_offset + len(segment_payload)] = segment_payload
                    self.segments.pop(seq_offset)
                else:
                    break  # short circuit because list is sorted
            return True


class H2Stream(TCPStream):
    def pop_frames(self) -> List[Frame]:
        """ Pop all available H2Frames """

        # If self.data starts with the http/2 magic bytes, pop them off
        if self.data.startswith(HTTP2_MAGIC):
            logger.debug('HTTP/2 magic bytes')
            self.data = self.data[len(HTTP2_MAGIC):]
            self.seq += len(HTTP2_MAGIC)

        frames = []
        while len(self.data) >= FRAME_HEADER_SIZE:
            frame, additional_size = Frame.parse_frame_header(memoryview(self.data[:FRAME_HEADER_SIZE]))
            if len(self.data) - FRAME_HEADER_SIZE < additional_size:
                # the frame has an incomplete body
                break
            self.data = self.data[FRAME_HEADER_SIZE:]
            frame.parse_body(memoryview(self.data[:additional_size]))
            self.data = self.data[additional_size:]
            self.seq += FRAME_HEADER_SIZE + additional_size
            frames.append(frame)
        return frames


class RemoteXPCSniffer:
    def __init__(self):
        self.dtx_message_helpers: MutableMapping[str, ParseDTXHelper] = {}
        self.plist_message_helpers: MutableMapping[str, ParsePlistHelper] = {}
        self._h2_streams: MutableMapping[str, H2Stream] = {}
        self._previous_frame_data: MutableMapping[str, bytes] = {}

    def process_packet(self, packet: Packet) -> None:
        if packet.haslayer(TCP) and packet[TCP].payload:
            self._process_tcp(packet)

    def _process_tcp(self, pkt: Packet) -> None:
        # we are going to separate TCP packets into TCP streams between unique
        # endpoints (ip/port) then, for each stream, we will create a new H2Stream
        # object and pass TCP packets into it H2Stream objects will take the bytes
        # from each TCP packet and add them to the stream.  No error correction /
        # checksum checking will be done. The stream will just overwrite its bytes
        # with whatever is presented in the packets. If the stream receives packets
        # out of order, it will add the bytes at the proper index.
        if pkt.haslayer(IP):
            net_pkt = pkt[IP]
            print("不是IPv6")
            print(net_pkt)
            return
        elif pkt.haslayer(IPv6):
            net_pkt = pkt[IPv6]
        else:
            print("不是iP 也不是 IPv6")
            return
        tcp_pkt = pkt[TCP]
        inbound = True
        server_port = 0
        local_port = 0
        src = ""
        des = ""
        src_port = 0
        des_port = 0

        if net_pkt.dst.endswith('::1'):
            inbound = False
            server_port = tcp_pkt.dport
            local_port = tcp_pkt.sport
            server_service = services[str(server_port)]
            src = "local"
            des = server_service
            src_port = local_port
            des_port = server_port
        else:
            server_port = tcp_pkt.sport
            local_port = tcp_pkt.dport
            server_service = services[str(server_port)]
            src = server_service
            des = "local"
            src_port = server_port
            des_port = local_port

        stream_key = create_stream_key(src, src_port, des, des_port)
        print()
        print()
        print(stream_key)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        print(current_time, stream_key)
        data = bytes(tcp_pkt.payload)
        
        folder_name = "{}/{}_{}".format(interface_folder, server_service, local_port)
        # create folder if not exists
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        global packet_id
        direction = "inbound" if inbound else "outbound"
        # formate packet_id 4 digit, add 0 in front
        packet_name = '{}/{}_{}.bin'.format(folder_name, str(packet_id).zfill(4), direction)
        with open(packet_name, 'wb') as file:
            file.write(data)
            logger.debug(f'write tcp packet payload data to: {packet_name}')
        hexStr = hexdump(data=data, result='return')
        # write hexStr to file
        name = '{}/{}_{}.txt'.format(folder_name, str(packet_id).zfill(4), direction)
        with open(name, 'w') as file:
            file.write(hexStr)
            # print("write tcp packet payload hex string to: ", name)
        packet_id += 1

        if "testmanagerd" in server_service or "instruments" in server_service:
            if stream_key not in self.dtx_message_helpers:
                helper = ParseDTXHelper()
                self.dtx_message_helpers[stream_key] = helper
            helper = self.dtx_message_helpers[stream_key]
            helper.parse_single_data(packet_name)
            return
        
        if "notification_proxy" in server_service or "remote.trusted" in server_service:
            if stream_key not in self.plist_message_helpers:
                helper = ParsePlistHelper()
                self.plist_message_helpers[stream_key] = helper
            helper = self.plist_message_helpers[stream_key]
            helper.process_single_data(packet_name)
            return

        if "openstdiosocket" in server_service:
            try:
                # content = data.decode('ascii', errors='replace')
                print("openstdiosocket data:")
                if len(data) == 16: 
                    print(data.decode('ascii', errors='replace'))
                else:
                    print(data)
            except Exception as e1:
                print("parse openstdiosocket failed")
                print("Get Exception %s",e1)

         
        stream = self._h2_streams.setdefault(
            stream_key, H2Stream(net_pkt.src, tcp_pkt.sport, net_pkt.dst, tcp_pkt.dport))
        stream_finished_assembling = stream.add(tcp_pkt, inbound=inbound)
        if stream_finished_assembling:  # if we just added something in order
            self._process_stream(stream)

    def _handle_data_frame(self, stream: H2Stream, frame: DataFrame) -> None:
        previous_frame_data = self._previous_frame_data.get(stream.key, b'')
        print("previous_frame_data length: ", len(previous_frame_data))
        print("current data frame length: ", len(frame.data))
        hexdump(frame.data)
        global xpcWrapperIndex, interface
        try:
            wrapper = XpcWrapper.parse(previous_frame_data + frame.data)
            print(wrapper.flags)
            print("message id: ", wrapper.message.message_id)
            # print("message: ", wrapper.message)
            print("magic: ", wrapper.magic)
            name = '{}/{}.bin'.format(interface_folder , xpcWrapperIndex)
            with open(name, 'wb') as file:
                file.write(previous_frame_data + frame.data)
                print("write xpc wrapper binary data to: ", name)
                xpcWrapperIndex += 1
            payload = wrapper.message.payload
            if payload is None:
                return None
            xpc_message = decode_xpc_object(payload.obj)
            print(222222222222222222)
        except ConstError:  # if we don't know what this payload is
            # 这里不需要加上previous_frame_data吗？
            print(33333333333333333333)
            global xcruntest_data, fileIndex, singleIndex
            singleFileName = "{}/single_data_{}.zip".format(interface_folder , singleIndex)
            with open(singleFileName, 'wb') as f:
                f.write(frame.data)
                print("write dataframe data to file:", singleFileName)
            singleIndex += 1

            xcruntest_data += frame.data
            fileName = "{}/captured_data_{}.zip".format(interface_folder , fileIndex)
            fileIndex += 1
            with open(fileName, 'wb') as f:
                f.write(xcruntest_data)
                print("write dataframe data to file:", fileName)
            logger.debug(
                f'New Data frame {stream.src}->{stream.dst} on HTTP/2 stream {frame.stream_id} TCP port {stream.dport}')
            # hexdump(frame.data[:64])
            # dataLeng = len(frame.data)
            # if dataLeng >= 256:
            #     hexdump(frame.data[:256])
            #     logger.debug(f'... {len(frame.data)} bytes')
            # else:
            #     hexdump(frame.data[:dataLeng])
            return
        except StreamError:
            print(4444444444444444)
            self._previous_frame_data[stream.key] = previous_frame_data + frame.data
            streamErrorFile = "{}/streamError.bin".format(interface_folder)
            with open(streamErrorFile, 'wb') as f:
                f.write(frame.data)
                print("write streamError data to file:", streamErrorFile)
            return

        if stream.key in self._previous_frame_data:
            self._previous_frame_data.pop(stream.key)

        if xpc_message is None:
            print(55555555555555555555)
            return

        logger.info(f'As Python Object (#{frame.stream_id}): {pformat(xpc_message)}')

        # print `pairingData` if exists, since it contains an inner struct
        if 'value' not in xpc_message:
            return
        message = xpc_message['value']['message']
        if 'plain' not in message:
            return
        plain = message['plain']['_0']
        if 'event' not in plain:
            return
        pairing_data = plain['event']['_0']['pairingData']['_0']['data']
        logger.info(PairingDataComponentTLVBuf.parse(pairing_data))

    def _handle_single_frame(self, stream: H2Stream, frame: Frame) -> None:
        logger.debug(f'New HTTP/2 frame: {stream.key} ({frame})')
        if isinstance(frame, HeadersFrame):
            logger.debug(
                f'{stream.src} opening stream {frame.stream_id} for communication on port {stream.dport}')
            hexdump(frame.data)
        elif isinstance(frame, GoAwayFrame):
            logger.debug(f'{stream.src} closing stream {frame.stream_id} on port {stream.sport}')
            hexdump(frame.data)
        elif isinstance(frame, DataFrame):
            self._handle_data_frame(stream, frame)
        else:
            print("unknow frame")

    def _process_stream(self, stream: H2Stream) -> None:
        for frame in stream.pop_frames():
            self._handle_single_frame(stream, frame)


@click.group()
def cli():
    """ Parse RemoteXPC traffic """
    pass


@cli.command()
@click.argument('file', type=click.Path(exists=True, file_okay=True, dir_okay=False))
def offline(file: str):
    """ Parse RemoteXPC traffic from a .pcap file """
    sniffer = RemoteXPCSniffer()
    for p in sniff(offline=file):
        sniffer.process_packet(p)


@cli.command()
@click.argument('iface')
def live(iface: str):
    """ Parse RemoteXPC live from a given network interface """
    sniffer = RemoteXPCSniffer()
    sniff(iface=iface, prn=sniffer.process_packet)


if __name__ == '__main__':
    # interface = sys.argv[1]
    print("try to sniff: ", interface)
    # while(True):
    #     try:
    #         sniffer = RemoteXPCSniffer()
    #         re = sniff(iface="utun6", prn=sniffer.process_packet)
    #         sniffer.stop_sniffing()
    #     except Exception as e:
    #         print("utun7 not ready")
    #         time.sleep(0.1)
    while(True):
        command = "ifconfig"  # or "ip link show" on Linux
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
        if interface in result:
            sniffer = RemoteXPCSniffer()
            re = sniff(iface=interface, prn=sniffer.process_packet)
        time.sleep(0.1)

    ##Xcode
    # stage = 0
    # while(True):
    #     command = "ifconfig"  # or "ip link show" on Linux
    #     result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
    #     if "utun8" in result:
    #         if stage == 1:
    #             stage = 2
    #     else:
    #         stage = 1
    #     if stage == 2:
    #         sniffer = RemoteXPCSniffer()
    #         re = sniff(iface="utun8", prn=sniffer.process_packet)
    #         # sniffer.stop_sniffing()
    #     time.sleep(0.1)