from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.syslog import SyslogService
from time import sleep
import json
from hyperframe.frame import DataFrame, Frame, GoAwayFrame, HeadersFrame, RstStreamFrame, SettingsFrame, \
    WindowUpdateFrame
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type, FileTransferType, XpcFlags, XpcWrapper, create_xpc_wrapper, decode_xpc_object
def type_serializer(o):
    # This will handle any unknown or non-native types.
    return f"<{o.__class__.__name__}>"

host = 'fd14:1a87:b0d6::1'  # randomized
port = 52735  # randomized

# fd97:8868:98dd::1/50784
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from collections import namedtuple
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap

from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.core_device.device_info import DeviceInfoService
from pymobiledevice3.remote.bridge_service import BridgeService
from pymobiledevice3.remote.installcoordination_proxy_service import InstallcoordinationProxyService
from bpylist2 import archiver
import plistlib

def parse_plist(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
        if data is not None:
            try:
                re = archiver.unarchive(data)
                print(re)
            except archiver.MissingClassMapping as e:
                print(plistlib.loads(data))
                raise e
            except plistlib.InvalidFileException:
                print(f'got an invalid plist: {data[:40]}')

def parse_dtx(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
        if data is not None:
            print()

def parse_xpc(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()
        if data is not None:
            xpc_message = XpcWrapper.parse(data)
            print(xpc_message)

# parse_plist("/Users/isan/Desktop/testmanaged/10.bin")
# parse_xpc("/Users/isan/Desktop/testmanaged/2.bin")
# parse_xpc("/Users/isan/runtest/interfaces/utun7/901.bin")





Process = namedtuple('process', 'pid name cpuUsage')

with RemoteServiceDiscoveryService((host, port)) as rsd:
    print(rsd)
    print(1)
    print(1)
    print(json.dumps(rsd.peer_info, default=type_serializer))
    print(1)
    print(1)
    print(1)
    with DvtSecureSocketProxyService(lockdown=rsd) as dvt:
        with Sysmontap(dvt) as sysmon:
            for process_snapshot in sysmon.iter_processes():
                entries = []
                for process in process_snapshot:
                    if (process['cpuUsage'] is not None) and (process['cpuUsage'] >= 3):
                        entries.append(Process(pid=process['pid'], name=process['name'], cpuUsage=process['cpuUsage']))

                print(entries)
exit(0)

# name = "/Users/isan/runtest/wrapper/70.bin"
# with open(name, 'rb') as file:
#     binary_data = file.read()
#     wrapper = XpcWrapper.parse(binary_data)
#     payload = wrapper.message.payload
#     if payload is None:
#         print(1111111111111)
#     xpc_message = decode_xpc_object(payload.obj)
#     print("ddd")

with RemoteServiceDiscoveryService((host, port)) as rsd:
    print(rsd)
    #copy device
    # with BridgeService(rsd) as bridge_service:
    #     name = "/Users/isan/runtest/wrapper/2.bin"
    #     with open(name, 'rb') as file:
    #         binary_data = file.read()
    #         dataFrame =  DataFrame(stream_id=1, data=binary_data)
    #         bridge_service.service._send_frame(dataFrame)
    #         re = bridge_service.service.receive_response()
    #         print(json.dumps(re, default=type_serializer))
        
    #     rstFrame = RstStreamFrame(stream_id=1, error_code=5)
    #     rstFrame1 = RstStreamFrame(stream_id=3, error_code=5)
    #     bridge_service.service._send_frame(rstFrame)
    #     bridge_service.service._send_frame(rstFrame1)
    # print(11111)

    with BridgeService(rsd) as bridge_service:
        re = bridge_service.service.send_receive_request({'XPCRequestDictionary': {'Command': 'CopyDevices','HostProcessName': 'CoreDeviceService'}})
        print(json.dumps(re, default=type_serializer))
        sleep(1)

        re1 = bridge_service.service.send_receive_request({'XPCRequestDictionary': {'Command': 'CopyDevices','HostProcessName': 'CoreDeviceService'}})
        print(json.dumps(re1, default=type_serializer))
    exit(0)
    # get device info 
    # with DeviceInfoService(rsd) as device_service:
    #     name = "/Users/isan/runtest/wrapper/34.bin"
    #     with open(name, 'rb') as file:
    #         binary_data = file.read()
    #         dataFrame =  DataFrame(stream_id=1, data=binary_data)
    #         device_service.service._send_frame(dataFrame)
    #         re = device_service.service.receive_response()
    #         print(json.dumps(re, default=type_serializer))
    #     rstFrame = RstStreamFrame(stream_id=1, error_code=5)
    #     rstFrame1 = RstStreamFrame(stream_id=3, error_code=5)
    #     device_service.service._send_frame(rstFrame)
    #     device_service.service._send_frame(rstFrame1)
    # print(2222)
    # with DeviceInfoService(rsd) as device_service:
    #     re = device_service.get_device_info()
    #     print(json.dumps(re, default=type_serializer))
    #     sleep(1)
    #     re1 = device_service.get_lockstate()
    #     print(json.dumps(re1, default=type_serializer))
    # exit(0)



    # with BridgeService(rsd) as bridge_service:
    #     name = "/Users/isan/runtest/wrapper/52.bin"
    #     with open(name, 'rb') as file:
    #         binary_data = file.read()
    #         dataFrame =  DataFrame(stream_id=1, data=binary_data)
    #         bridge_service.service._send_frame(dataFrame)
    #         re = bridge_service.service.receive_response()
    #         print(json.dumps(re, default=type_serializer))
    #     rstFrame = RstStreamFrame(stream_id=1, error_code=5)
    #     rstFrame1 = RstStreamFrame(stream_id=3, error_code=5)
    #     bridge_service.service._send_frame(rstFrame)
    #     bridge_service.service._send_frame(rstFrame1)
    
    print(33333)

    # # 好像是查询某个bundleID的安装情况
    # with InstallcoordinationProxyService(rsd) as install_service:  #这个没有RST
    #     name = "/Users/isan/runtest/wrapper/66.bin"
    #     with open(name, 'rb') as file:
    #         binary_data = file.read()
    #         dataFrame =  DataFrame(stream_id=1, data=binary_data)
    #         install_service.service._send_frame(dataFrame)
    #         re = install_service.service.receive_response()
    #         print(json.dumps(re, default=type_serializer))
    #     rstFrame = RstStreamFrame(stream_id=1, error_code=5)
    #     rstFrame1 = RstStreamFrame(stream_id=3, error_code=5)
    #     install_service.service._send_frame(rstFrame)
    #     install_service.service._send_frame(rstFrame1)
    # print(44444)
    # with InstallcoordinationProxyService(rsd) as install_service:
    #     re = install_service.service.send_receive_request({'RequestVersion': XpcUInt64Type(1), 'BundleID': 'com.apple.test.WebDriverAgentRunner-Runner', 'ProtocolVersion': XpcUInt64Type(1), 'RequestType': XpcUInt64Type(4)})
    #     print(json.dumps(re, default=type_serializer))
    #     sleep(1)
    # exit(0)



    with InstallcoordinationProxyService(rsd, involveUpload=True) as install_service:
        # try to receive two header frame
        header_frame_count = 0
        while header_frame_count < 2:
            frame = install_service.service._receive_frame()
            print("get frame: ", frame)
            if isinstance(frame, HeadersFrame):
                header_frame_count += 1
        # InstallcoordinationProxyService open stream_id=5
        upload_stream = 5
        flags = XpcFlags.ALWAYS_SET | XpcFlags.FILE_TX_STREAM_REQUEST
        # flags = XpcFlags.ALWAYS_SET

        install_service.service._send_frame(HeadersFrame(stream_id=upload_stream, flags=['END_HEADERS']))
        # data = XpcWrapper.build({'flags': flags})
        # wrapper = XpcWrapper.parse(data)
        # install_service.service._send_frame(DataFrame(stream_id=upload_stream, data=data))

        print("tttttt")
        
        # # send asset size request
        # dic = {"AssetSize": XpcUInt64Type(33461),
        #         "AssetStreamFD": FileTransferType(18446744073709551615),
        #         "InstallMessageType": XpcUInt64Type(1),
        #         "ProtocolVersion": XpcUInt64Type(1),
        #         "RemoteInstallOptions": {"AIOverride": XpcUInt64Type(1),
        #                                 "BundleID": "com.apple.test.WebDriverAgentRunner-Runner",
        #                                 "BundleVersion": "14",
        #                                 "IconDataType": XpcUInt64Type(0),
        #                                 "Importance": XpcUInt64Type(2),
        #                                 "InstallMode": XpcUInt64Type(1),
        #                                 "InstallableType": XpcUInt64Type(0),
        #                                 "LocalizedName": "Digital Lab Runner",
        #                                 "ProfileErrorsFatal": True,
        #                                 "StashOption": XpcUInt64Type(0)},
        #         "RequestType": XpcUInt64Type(1),
        #         "RequestVersion": XpcUInt64Type(1)}
        
        # name = "/Users/isan/runtest/wrapper/70.bin"
        # with open(name, 'rb') as file:
        #     binary_data = file.read()
        #     dataFrame =  DataFrame(stream_id=1, data=binary_data)
        #     install_service.service._send_frame(dataFrame)
            
        # # install_service.service.send_request(dic)

        # # send zip file
        # with open('/Users/isan/runtest/test_upload.zip', 'rb') as f:
        #     data = f.read()
        #     install_service.service._send_frame(DataFrame(stream_id=upload_stream, data=data))
        # # send end of file
        # install_service.service._send_frame(DataFrame(stream_id=upload_stream, flags=['END_STREAM']))
        # install_service.service.receive_response()

        sleep(10)