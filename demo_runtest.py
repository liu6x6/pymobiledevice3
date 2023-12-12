from pymobiledevice3.services.remote_server import MessageAux, NSUUID, XCTCapabilitiesArchive
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.syslog import SyslogService
from time import sleep
import json
from hyperframe.frame import DataFrame, Frame, GoAwayFrame, HeadersFrame, RstStreamFrame, SettingsFrame, \
    WindowUpdateFrame
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type, FileTransferType, XpcFlags, XpcWrapper, XpcFileTransferType, \
    create_xpc_wrapper, decode_xpc_object
import uuid
import os
from construct import StreamError
from pymobiledevice3.exceptions import StreamClosedError



def type_serializer(o):
    # This will handle any unknown or non-native types.
    return f"<{o.__class__.__name__}>"

host = 'fdb0:b5dd:d72::1'  # randomized
port = 59655  # randomized


from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from collections import namedtuple
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap
from pymobiledevice3.services.testmanaged import TestmanagerdService
from pymobiledevice3.services.notification_proxy import NotificationProxyService
from pymobiledevice3.services.remote_trusted_service import RemoteTrustedService

from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.core_device.device_info import DeviceInfoService
from pymobiledevice3.remote.core_device.open_stdio_socket import Openstdiosocket

from pymobiledevice3.remote.bridge_service import BridgeService
from pymobiledevice3.remote.installcoordination_proxy_service import InstallcoordinationProxyService
from bpylist2 import archiver
import plistlib
from pymobiledevice3.services.heartbeat import HeartbeatService

from pymobiledevice3.services.dvt.instruments.condition_inducer import ConditionInducer

SequenceNumber = 1
# def send_heartbeat(rsd: RemoteServiceDiscoveryService):
#     global SequenceNumber
#     while True:
#         re = rsd.service.send_receive_request({'MessageType': 'Heartbeat', 'SequenceNumber': XpcUInt64Type(SequenceNumber)})
#         print(json.dumps(re, default=type_serializer))
#         SequenceNumber += 1
#         sleep(30)

with RemoteServiceDiscoveryService((host, port)) as rsd:
    print(rsd)
    # exit(0)
    
    # call send_heartbeat in a new thread
    # import threading
    # t = threading.Thread(target=send_heartbeat, args=(rsd,))
    # t.start()
    
    # try:
    #     HeartbeatService(rsd).start()
    # except ConnectionAbortedError:
    #     print('device disconnected, awaiting reconnect')
    
    # mobile.notification_proxy.shim.remote_51722
    notification =  NotificationProxyService(rsd)
    # service.send_plist({'Label': label, 'ProtocolVersion': '2', 'Request': 'RSDCheckin'})
    notification.service.send_plist({'Command': 'ObserveNotification', 'Name': 'com.apple.mobile.keybagd.lock_status'})
    notification.service.send_plist({'Command': 'ObserveNotification', 'Name': 'com.apple.LaunchServices.ApplicationsChanged'})
    notification.service.send_plist({'Command': 'ObserveNotification', 'Name': 'AMDNotificationFaceplant'})
    # re1 = notification.service.recv_plist()
    # re2 = notification.service.recv_plist()
    
    #copy device
    with BridgeService(rsd) as bridge_service:  #local 51723
        re = bridge_service.service.send_receive_request({'XPCRequestDictionary': {'Command': 'CopyDevices','HostProcessName': 'CoreDeviceService'}})
        print(json.dumps(re, default=type_serializer))
        rstFrame = RstStreamFrame(stream_id=1, error_code=5)
        rstFrame1 = RstStreamFrame(stream_id=3, error_code=5)
        bridge_service.service._send_frame(rstFrame)
        bridge_service.service._send_frame(rstFrame1)
    
    remoteTrusted = RemoteTrustedService(rsd)
    remoteTrusted.service.send_plist({'Label': 'CoreDeviceService', 'ProtocolVersion': '2', 'Request': 'QueryType'})
    remoteTrusted.service.send_plist({'Key': 'PasswordProtected', 'Label': 'CoreDeviceService', 'ProtocolVersion': '2', 'Request': 'GetValue'})
    
    ## two testmanaged
    # testmanged5 stage 1 begin
    testmanged5 = TestmanagerdService(rsd)
    testmanged5.perform_handshake()
    channel_identifier = "dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface"
    channel51 = testmanged5.make_channel(channel_identifier)
    args51 = MessageAux()
    args51.append_obj({"capabilities-dictionary":{}})
    # args51.append_obj({})
    testmanged5.send_message(channel=channel51, selector="_IDE_initiateControlSessionWithCapabilities:", args=args51)
    ret = channel51.receive_plist()

    args52 = MessageAux()
    args52.append_obj(["/var/mobile/Library/Logs/CrashReporter/"])
    args52.append_obj(['WebDriverAgentRunner-Runner', 'FrontBoard', 'WebDriverAgentRunner', 'debugserver', 'DTServiceHub', 'SpringBoard', 'runningboardd', 'xctest', 'assertiond', 'backboardd', 'testmanagerd'])
    testmanged5.send_message(channel=channel51, selector="_IDE_collectNewCrashReportsInDirectories:matchingProcessNames:", args=args52)
    print("prepare to receive message")
    ret1 = channel51.receive_plist()
    # print(ret1)
    sleep(1)
    print("ddd")
    # testmanged5 stage 1 end


    # testmanged6 stage 1 begin
    testmanged6 = TestmanagerdService(rsd)
    testmanged6.perform_handshake()
    channel_identifier = "dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface"
    channel61 = testmanged6.make_channel(channel_identifier)

    capabilities = {
         "capabilities-dictionary":{
            "expected failure test capability": 1,
            "test case run configurations": 1,
            "test timeout capability": 1,
            "test iterations":1,
            "request diagnostics for specific devices":1,
            "delayed attachment transfer":1,
            "skipped test capability":1,
            "daemon container sandbox extension":1,
            "ubiquitous test identifiers":1,
            "XCTIssue capability":1
         }
        }
    
    sessionIdentifier = NSUUID(bytes=os.urandom(16), version=4)
    args61 = MessageAux()
    args61.append_obj(sessionIdentifier)
    capa = XCTCapabilitiesArchive()
    capa["capabilities-dictionary"] = {
            "expected failure test capability": 1,
            "test case run configurations": 1,
            "test timeout capability": 1,
            "test iterations":1,
            "request diagnostics for specific devices":1,
            "delayed attachment transfer":1,
            "skipped test capability":1,
            "daemon container sandbox extension":1,
            "ubiquitous test identifiers":1,
            "XCTIssue capability":1
         }
    args61.append_obj(capabilities)
    selector = "_IDE_initiateSessionWithIdentifier:capabilities:"

    testmanged6.send_message(channel=channel61, selector=selector, args=args61)
    ret1 = channel61.receive_plist()
    print(ret1)
    # testmanged6 stage 1 end

    # 好像是查询某个bundleID的安装情况
    install_service1 = InstallcoordinationProxyService(rsd)
    install_service1.connect()
    re = install_service1.service.send_request({'RequestVersion': XpcUInt64Type(1), 'BundleID': 'com.apple.test.WebDriverAgentRunner-Runner', 'ProtocolVersion': XpcUInt64Type(1), 'RequestType': XpcUInt64Type(4)})
    print(json.dumps(re, default=type_serializer))
    
    print("==================================================")
    sleep(0.5)
    install_service2 = InstallcoordinationProxyService(rsd, involveUpload=True)
    install_service2.connect()
    # try to receive two header frame
    # header_frame_count = 0
    # while header_frame_count < 2:
    #     frame = install_service.service._receive_frame()
    #     print("get frame: ", frame)
    #     if isinstance(frame, HeadersFrame):
    #         header_frame_count += 1
    # InstallcoordinationProxyService open stream_id=5
    sleep(1)
    upload_stream = 5
    flags = XpcFlags.ALWAYS_SET | XpcFlags.FILE_TX_STREAM_REQUEST
    install_service2.service._send_frame(HeadersFrame(stream_id=5, flags=['END_HEADERS']))

    request_msg_id = 0x06
    xpc_payload = {
        'message_id': request_msg_id,
        'payload': {'obj': None}
    }

    xpc_wrapper = {
        'flags': flags,
        'message': xpc_payload
    }
   
    wrapperdata = XpcWrapper.build(xpc_wrapper)
    install_service2.service._send_frame(DataFrame(stream_id=upload_stream, data=wrapperdata))
    print(" push the asset size file")
    
    # # send asset size request
    dic = {"AssetSize": XpcUInt64Type(33461),
            "AssetStreamFD": XpcFileTransferType({"s": XpcUInt64Type(18446744073709551615)}, XpcUInt64Type(request_msg_id)),
            # {"msg_id": 8, "data": {"s": 18446744073709551615}}, 
            "InstallMessageType": XpcUInt64Type(1),
            "ProtocolVersion": XpcUInt64Type(1),
            "RemoteInstallOptions": {"AIOverride": XpcUInt64Type(1),
                                    "BundleID": "com.apple.test.WebDriverAgentRunner-Runner",
                                    "BundleVersion": "14",
                                    "IconDataType": XpcUInt64Type(0),
                                    "Importance": XpcUInt64Type(2),
                                    "InstallMode": XpcUInt64Type(1),
                                    "InstallableType": XpcUInt64Type(0),
                                    "LocalizedName": "Digital Lab Runner",
                                    "ProfileErrorsFatal": True,
                                    "StashOption": XpcUInt64Type(0)},
            "RequestType": XpcUInt64Type(1),
            "RequestVersion": XpcUInt64Type(1)}
    install_service2.service.send_request(dic)
    sleep(1)
    
    # name = "/Users/xiao/Desktop/turn/11-15/utun5/64.bin"
    # with open(name, 'rb') as file:
    #     binary_data = file.read()
    #     dataFrame =  DataFrame(stream_id=1, data=binary_data)
    #     install_service2.service._send_frame(dataFrame)


    # print("1111 step2")
    # install_service2.service._send_frame(DataFrame(stream_id=5, data=wrapperdata))
    # # install_service2.service._receive_frame()
    # print(111)

    # install_service2.service._receive_frame()
    # sleep(1)
    # install_service2.service._receive_frame()
    # zip_file_path = "/Users/xiao/Desktop/turn/003/utun7-02/single_data_0.zip"
    # with open(zip_file_path, 'rb') as file:
    #     binary_data = file.read()
    #     dataFrame =  DataFrame(stream_id=upload_stream, data=binary_data)
    #     install_service2.service._send_frame(dataFrame)

    # ## send end of file to stream 5 and should get a RstStreamFrame(stream_id=5, flags=[]): error_code=5) from remote
    # install_service2.service._send_frame(DataFrame(stream_id=upload_stream, flags=['END_STREAM']))

    # # while True:
    # install_service2.service._receive_frame()
    # install_service2.service._receive_frame()


    # better to send same data we saved on the disk
    # with AppServiceService(rsd) as app_service:
    #     print("trying to launch WDA")
    #     # app_service.launch_application6()
    #     zip_file_path = "/Users/xiao/Desktop/turn/11-15/utun5/single_data_0.zip"
    #     with open(zip_file_path, 'rb') as file:
    #         binary_data = file.read()
    #         app_service.launch_application_raw(binary_data)
        
       

     #upload zip file
    print(" push the ZIP file")
    zip_file_path = "/Users/xiao/Desktop/turn/12-10/003/utun7/single_data_0.zip"
    with open(zip_file_path, 'rb') as file:
        binary_data = file.read()
        # # update date and time
        # original_sequence = bytes.fromhex("127B6157")
        # current_datetime = datetime.now()
        # dos_time = current_datetime.hour << 11 | current_datetime.minute << 5 | current_datetime.second // 2
        # dos_date = (current_datetime.year - 1980) << 9 | current_datetime.month << 5 | current_datetime.day
        # # Combine time and date into a 4-byte sequence
        # replacement_sequence = dos_time.to_bytes(2, byteorder='little') + dos_date.to_bytes(2, byteorder='little')
        # updated_content = binary_data.replace(original_sequence, replacement_sequence)

        dataFrame =  DataFrame(stream_id=upload_stream, data=binary_data)
        install_service2.service._send_frame(dataFrame)

    ## send end of file to stream 5 and should get a RstStreamFrame(stream_id=5, flags=[]): error_code=5) from remote
    install_service2.service._send_frame(DataFrame(stream_id=upload_stream, flags=['END_STREAM']))
    sleep(1)

    print("loop to receive all process message")
    ## receive install complete message
    re = {}
    while "DBSequence" not in re:
        try:
            re = install_service2.service.receive_response()
            print(re)
        except StreamClosedError:
            print("data 不完整")
            continue

    print("received install complete message")
    rstFrame1 = RstStreamFrame(stream_id=1, error_code=5)
    rstFrame3 = RstStreamFrame(stream_id=3, error_code=5)
    install_service2.service._send_frame(rstFrame1)
    install_service2.service._send_frame(rstFrame3)
    sleep(1)

    ## need open openstdiosocket
    ## and get the output uuid
    print("open openstdiosocket")

    openstdioSocket = Openstdiosocket(rsd)
    io_uuid = openstdioSocket.get_uuid()
    print("get the std uuid = " + str(io_uuid))

    print("try to launch WDA")
    sessioinId = str(uuid.UUID(bytes=sessionIdentifier.bytes)).upper()
    with AppServiceService(rsd) as app_service:
        app_service.test_launch_application(re, sessionId=sessioinId,io_uuid=io_uuid)

    sleep(100)
    exit(0)
    # should get lots of progress message from server
