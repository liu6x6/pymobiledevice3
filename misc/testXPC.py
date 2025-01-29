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
import xml
from typing import IO, Optional

import click
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff




if __name__ == '__main__':
    # interface = sys.argv[1]
    fileName = "/Users/xiao/packets/utun7-go1/13.bin"
    with open(fileName, 'rb') as f:
        data = f.read()
        print("write dataframe data to file:", fileName)
        try:
            wrapper = XpcWrapper.parse(data)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        print("message flags:",wrapper.flags)
 
        # print("message: ", wrapper.message)
        print("message magic: ", wrapper.magic)
        message = wrapper.message
        print("message id: ", message.message_id)
            
        payload = message.payload
        print("message payload: ", payload)


