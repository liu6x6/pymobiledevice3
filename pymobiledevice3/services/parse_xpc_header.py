from construct import ConstError, StreamError
from pymobiledevice3.services.remote_server import message_aux_t_struct
import os
import io
import plistlib
from bpylist2 import archiver
from bpylist2.archiver import ArchivedObject
from queue import Empty, Queue


from pymobiledevice3.services.remote_server import NSURL, NSUUID, Channel, ChannelFragmenter, MessageAux, \
    XCTestConfiguration, dtx_message_header_struct, dtx_message_payload_header_struct

class ParseDTXHelper():
    previous_data = b''
    channelFragmenter = None

    out_previous_data = b''
    out_channelFragmenter = None
    inbounding = True
    def process_data(self, unitData):
        try:
            if len(unitData) < 32:
                print("data 不完整")
                self.previous_data = unitData
                return
            # read dtx_message_header_struct.sizeof() data from the unitData
            headerData = unitData[:dtx_message_header_struct.sizeof()]
            mheader = dtx_message_header_struct.parse(headerData)
            # print("mheader: ", mheader)
            if mheader.fragmentCount > 1 and mheader.fragmentId == 0:
                # when reading multiple message fragments, the first fragment contains only a message header
                print("mheader.fragmentCount > 1 and mheader.fragmentId == 0")
                return
            # read mheader.length bytes behind the header from the unitData
            fdata = unitData[dtx_message_header_struct.sizeof():dtx_message_header_struct.sizeof()+mheader.length]
            # print("fdata: ", len(fdata))
            if len(fdata) != mheader.length:
                print("data 不完整")
                self.previous_data = unitData
                return

            chanelFra = self.channelFragmenter if self.channelFragmenter else ChannelFragmenter()
            chanelFra.add_fragment(mheader, fdata)
            stream = io.BytesIO(chanelFra.get())
            pheader = dtx_message_payload_header_struct.parse_stream(stream)
            # print("pheader: ", pheader)
            compression = (pheader.flags & 0xFF000) >> 12
            if compression:
                print("NotImplementedError('Compressed')")
                # raise NotImplementedError('Compressed')

            if pheader.auxiliaryLength:
                aux_struct= message_aux_t_struct.parse_stream(stream)
                aux = aux_struct.aux
            else:
                aux = None
            
            # print("aux: ")
            # pp.pprint(aux)
            obj_size = pheader.totalLength - pheader.auxiliaryLength
            data = stream.read(obj_size) if obj_size else None
            
            if data is not None:
                if len(data) != obj_size:
                    print("data 不完整")
                    self.previous_data = unitData
                    return
                try:
                    data = archiver.unarchive(data)
                except archiver.MissingClassMapping as e:
                    print("archiver.MissingClassMapping")
                    result = plistlib.loads(data)
                    print("result: ", result)
                    print(e)
                    # raise e
                except plistlib.InvalidFileException:
                    print(f'got an invalid plist: {data[:40]}')
            # print("data:", data)
            self.printData(mheader,fdata,pheader,aux,data)
            self.previous_data = b''
            # check if there is any remaining data in unitData
            if len(unitData) > dtx_message_header_struct.sizeof()+mheader.length:
                remaining_data = unitData[dtx_message_header_struct.sizeof()+mheader.length:]
                print()
                print("there is remaining data: {} to process".format(len(remaining_data)))
                self.process_data(remaining_data)
        except ConstError:
            print("不认识的data")
        except Empty:
            print(len(unitData))
            print(len(self.previous_data))
            print(dtx_message_header_struct.sizeof())
            print(mheader.length)
            self.previous_data = unitData[dtx_message_header_struct.sizeof()+mheader.length:]
            print(len(self.previous_data))
            self.channelFragmenter = chanelFra
            print("Empty")
            return
        except StreamError:
            print("data 不完整 StreamError")
            self.previous_data = unitData
            return

    def printData(self,mheader,fdata,pheader,aux,data):
        if data is None and aux is None:
            print("empty DTXMessage")
            # print("mheader: ", mheader)
            # print("fdata: ", len(fdata))
            # print("pheader: ", pheader)
            # return
        if data == "_XCT_logDebugMessage:":
            print("get _XCT_logDebugMessage:") #data is a list
            for it in aux:
                print(it.value)
            # return
        print("DTX Message =======")
        print("mheader: ", mheader)
        print("fdata: ", len(fdata))
        print("pheader: ", pheader)

        print("aux: ")
        # pp.pprint(aux)
        if aux is None:
            print("aux is null")
        else:
            for it in aux:
                print(it.value)
        
        print("data:",data)
        
    

    def process_out_data(self, unitData):
        try:
            if len(unitData) < 32:
                print("data 不完整")
                self.out_previous_data = unitData
                return
            # read dtx_message_header_struct.sizeof() data from the unitData
            headerData = unitData[:dtx_message_header_struct.sizeof()]
            mheader = dtx_message_header_struct.parse(headerData)
            # print("mheader: ", mheader)
            if mheader.fragmentCount > 1 and mheader.fragmentId == 0:
                # when reading multiple message fragments, the first fragment contains only a message header
                print("mheader.fragmentCount > 1 and mheader.fragmentId == 0")
                return
            # read mheader.length bytes behind the header from the unitData
            fdata = unitData[dtx_message_header_struct.sizeof():dtx_message_header_struct.sizeof()+mheader.length]
            # print("fdata: ", len(fdata))
            if len(fdata) != mheader.length:
                print("data 不完整")
                self.out_previous_data = unitData
                return

            chanelFra = self.out_channelFragmenter if self.out_channelFragmenter else ChannelFragmenter()
            chanelFra.add_fragment(mheader, fdata)
            stream = io.BytesIO(chanelFra.get())
            pheader = dtx_message_payload_header_struct.parse_stream(stream)
            # print("pheader: ", pheader)
            compression = (pheader.flags & 0xFF000) >> 12
            if compression:
                print("NotImplementedError('Compressed')")
                # raise NotImplementedError('Compressed')

            if pheader.auxiliaryLength:
                aux_struct= message_aux_t_struct.parse_stream(stream)
                aux = aux_struct.aux
            else:
                aux = None
            # print("aux: ")
            # pp.pprint(aux)
            obj_size = pheader.totalLength - pheader.auxiliaryLength
            data = stream.read(obj_size) if obj_size else None
            
            if data is not None:
                if len(data) != obj_size:
                    print("data 不完整")
                    self.out_previous_data = unitData
                    return
                try:
                    data = archiver.unarchive(data)
                except archiver.MissingClassMapping as e:
                    print("archiver.MissingClassMapping")
                    result = plistlib.loads(data)
                    print("result: ", result)
                    print(e)
                    # raise e
                except plistlib.InvalidFileException:
                    print(f'got an invalid plist: {data[:40]}')
            # print("data:", data)
            self.printData(mheader,fdata,pheader,aux,data)

            self.out_previous_data = b''
            # check if there is any remaining data in unitData
            if len(unitData) > dtx_message_header_struct.sizeof()+mheader.length:
                remaining_data = unitData[dtx_message_header_struct.sizeof()+mheader.length:]
                print()
                print("there is remaining data: {} to process".format(len(remaining_data)))
                self.process_out_data(remaining_data)
        except ConstError:
            print("不认识的data")
        except Empty:
            print(len(unitData))
            print(len(self.out_previous_data))
            print(dtx_message_header_struct.sizeof())
            print(mheader.length)
            self.out_previous_data = unitData[dtx_message_header_struct.sizeof()+mheader.length:]
            print(len(self.out_previous_data))
            self.out_channelFragmenter = chanelFra
            print("Empty")
            return
        except StreamError:
            print("data 不完整")
            self.out_previous_data = unitData
            return


    def parse_single_data(self, path):
        try:
            self.inbounding = ("inbound" in path)
            old_data = self.previous_data if self.inbounding else self.out_previous_data
            with open(path, 'rb') as f:
                fileData = f.read()
                unitData = old_data + fileData
                print(path, len(fileData))
                print("previous_data: ", len(old_data))
                print("unitData: ", len(unitData))
                if self.inbounding:
                    self.process_data(unitData)
                else:
                    self.process_out_data(unitData)
        except Exception as e:
            # pass
            print(e)
            print(path, '  failed')


def lookfor_header(path):
    with open(path, 'rb') as f:
        headerSize = dtx_message_header_struct.sizeof()
        fileData = f.read()
        fileLength = len(fileData)
        startIndex = 0
        while startIndex <= fileLength - headerSize + 1:
            print(startIndex)
            try:
                headerData = fileData[startIndex:startIndex+headerSize]
                mheader = dtx_message_header_struct.parse(headerData)
                print(mheader)
                break
            except Exception as e:
                pass
            startIndex += 1

def parse_plist_bin(path):
    with open(path, 'rb') as f:
        data = f.read()
        try:
            data = archiver.unarchive(data)
            print("data:", data)
        except archiver.MissingClassMapping as e:
            print("111111111111")
            result = plistlib.loads(data)
            print(result)
            raise e
        except plistlib.InvalidFileException:
            print(f'got an invalid plist: {data[:40]}')

def parseXCTestConfiguration():
    name = '/Users/isan/XCTestConfiguration.bin'
    with open(name, 'rb') as file:
        data = file.read()
        data = archiver.unarchive(data)

if __name__ == '__main__':
    helper = ParseDTXHelper()
    index = 1
    while index <= 263:
        directions = ['inbound', 'outbound']
        for direction in directions:
            path = '/Users/isan/runtest/xcode_1117_部分安装_62/dt.testmanagerd.remote_50705/{}_{}.bin'.format(str(index).zfill(4), direction)
            if os.path.isfile(path):
                print()
                print()
                helper.parse_single_data(path)
                break
        index += 1
