import os
import logging
import plistlib
import struct
from typing import Mapping, Optional

from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionTerminatedError, NoDeviceConnectedError, \
    PyMobileDevice3Exception

class ParsePlistHelper():
    data = b''
    out_data = b''
    cursor = 0
    out_cursor = 0
    def process_single_data(self, path):
        with open(path, 'rb') as f:
            print(path)
            if "inbound" in path:
                self.data = self.data + f.read()
                self.process_data()
            else:
                self.out_data = self.out_data + f.read()
                self.process_out_data()

    def process_out_data(self):
        current_cursor = self.out_cursor
        while current_cursor < len(self.out_data):
            headerData = self.out_data[current_cursor:current_cursor+4]
            if(len(headerData) != 4):
                break
            payloadLength = struct.unpack('>' + 'L', headerData)[0]
            current_cursor = current_cursor + 4
            # print(payloadLength)
            payload = self.out_data[current_cursor:current_cursor+payloadLength]
            current_cursor = current_cursor+payloadLength
            if len(payload) != payloadLength:
                print("data 不完整")
                break
            try:
                re = plistlib.loads(payload)
                print(re)
            except plistlib.InvalidFileException:
                raise PyMobileDevice3Exception(f'parse_plist invalid data: {payload[:100].hex()}')
            self.out_cursor = current_cursor

    def process_data(self):
        current_cursor = self.cursor
        while current_cursor < len(self.data):
            headerData = self.data[current_cursor:current_cursor+4]
            if(len(headerData) != 4):
                break
            payloadLength = struct.unpack('>' + 'L', headerData)[0]
            current_cursor = current_cursor + 4
            # print(payloadLength)
            payload = self.data[current_cursor:current_cursor+payloadLength]
            current_cursor = current_cursor+payloadLength
            if len(payload) != payloadLength:
                print("data 不完整")
                break
            try:
                re = plistlib.loads(payload)
                print(re)
            except plistlib.InvalidFileException:
                raise PyMobileDevice3Exception(f'parse_plist invalid data: {payload[:100].hex()}')
            self.cursor = current_cursor

if __name__ == '__main__':
    helper = ParsePlistHelper()
    index = 30
    basePath = "/Users/isan/runtest/xcode_1211/mobile.lockdown.remote.trusted_60826"
    while index <= 41:
        directions = ['inbound', 'outbound']
        for direction in directions:
            path = '{}/{}_{}.bin'.format(basePath,str(index).zfill(4), direction)
            if os.path.isfile(path):
                print()
                helper.process_single_data(path)
                break
        index += 1
 
