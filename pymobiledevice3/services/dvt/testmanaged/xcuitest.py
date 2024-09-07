import logging
import time
import uuid
from typing import Any, Mapping, Optional

from bpylist2 import archiver
from packaging.version import Version

from pymobiledevice3.exceptions import AppNotInstalledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.dvt_testmanaged_proxy import DvtTestmanagedProxyService
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.house_arrest import HouseArrestService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.remote_server import NSURL, NSUUID, Channel, ChannelFragmenter, MessageAux, \
    XCTestConfiguration, dtx_message_header_struct, dtx_message_payload_header_struct

from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.core_device.openstdiosocket import Openstdiosocket
from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


logger = logging.getLogger(__name__)


class XCUITestService:
    IDENTIFIER = "dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface"
    XCODE_VERSION = 36  # not important

    def __init__(self, service_provider: LockdownServiceProvider):
        self.service_provider = service_provider
        # self.pctl = self.init_process_control()
        self.product_major_version = Version(service_provider.product_version).major
        self.rsd = service_provider

    async def run(
        self,
        bundle_id: str,
        test_runner_env: Optional[dict] = None,
        test_runner_args: Optional[list] = None,
    ):
        
        # TODO: it seems the protocol changed when iOS>=17
        session_identifier = NSUUID.uuid4()
        app_info = get_app_info(self.service_provider, bundle_id)
        logger.info("app_info = %s",app_info)

        xctest_configuration = generate_xctestconfiguration(
            app_info, session_identifier, bundle_id, test_runner_env, test_runner_args
        )
        # xctest_path = f"/tmp/{str(session_identifier).upper()}.xctestconfiguration"  # yapf: disable

        # self.setup_xcuitest(bundle_id, xctest_path, xctest_configuration)
        # dvt1,dvt2 = self.init_connection()
        dvt1 = DvtTestmanagedProxyService(lockdown=self.rsd)
        dvt1.perform_handshake()

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

        chan1 = self.start_channel_with_capabilities(session_identifier,dvt=dvt1, capabilities=capabilities)

        # chan2 = self.start_channel_with_cap(dvt2,capabilities={"capabilities-dictionary":{}})
        
        # dvt1, chan1, dvt2, chan2 = self.init_ide_channels(session_identifier)

        pid = await self.launch_test_app17(
            app_info, bundle_id, test_runner_env, test_runner_args,session_identifier
        )
        
        logger.info("Runner started with pid:%d, waiting for testBundleReady", pid)

        dvt2 = DvtTestmanagedProxyService(lockdown=self.rsd)
        dvt2.perform_handshake()

        chan2 = dvt2.make_channel(self.IDENTIFIER)
        args51 = MessageAux()
        args51.append_obj({"capabilities-dictionary":{}})
         # args51.append_obj({})
        dvt2.send_message(channel=chan2, selector="_IDE_initiateControlSessionWithCapabilities:", args=args51)
        ret = chan2.receive_plist()

        logger.info("dvt 2 authorize_test_process_id=%d",pid)
        self.authorize_test_process_id(chan2, pid)

        logger.info("dvt1 start_channel_with_XCTestManager_IDEInterface")

        chan11 = dvt1.make_channel("dtxproxy:XCTestDriverInterface:XCTestManager_IDEInterface")
        # chan11 = self.start_channel_with_XCTestManager_IDEInterface(dvt1,"dtxproxy:XCTestDriverInterface:XCTestManager_IDEInterface")

        logger.info("start_executing_test_plan_with_protocol_version chan11")
        self.start_executing_test_plan_with_protocol_version(dvt1, self.XCODE_VERSION,channel=chan11)

        # TODO: boradcast message is not handled
        # TODO: RemoteServer.receive_message is not thread safe and will block if no message received
        try:
            self.dispatch(dvt2, chan2)
            self.dispatch(dvt1, chan11)
        except KeyboardInterrupt:
            logger.info("Signal Interrupt catched")
        finally:
            logger.info("Killing UITest with pid %d ...", pid)
            # self.pctl.kill(pid)
            dvt1.close()
            dvt2.close()

    def dispatch(self, dvt: DvtTestmanagedProxyService, chan: Channel):
        while True:
            self.dispatch_proxy(dvt, chan)

    def dispatch_proxy(self, dvt: DvtTestmanagedProxyService, chan: Channel):
        # Ref code:
        # https://github.com/danielpaulus/go-ios/blob/a49a3582ef4438fee794912c167d2cccf45d8efa/ios/testmanagerd/xcuitestrunner.go#L182
        # https://github.com/alibaba/tidevice/blob/main/tidevice/_device.py#L1117

        key, value = dvt.recv_plist(chan)
        value = value and value[0].value.strip()
        if key == "_XCT_logDebugMessage:":
            logger.debug("logDebugMessage: %s", value)
        elif key == "_XCT_testRunnerReadyWithCapabilities:":
            logger.info("testRunnerReadyWithCapabilities: %s", value)
            self.send_response_capabilities(dvt, chan, dvt.cur_message)
        else:
            # There are still unhandled messages
            # - _XCT_testBundleReadyWithProtocolVersion:minimumVersion:
            # - _XCT_didFinishExecutingTestPlan
            logger.info("unhandled %s %r", key, value)

    def send_response_capabilities(
        self, dvt: DvtTestmanagedProxyService, chan: Channel, cur_message: int
    ):
        pheader = dtx_message_payload_header_struct.build(
            dict(flags=3, auxiliaryLength=0, totalLength=0)
        )
        mheader = dtx_message_header_struct.build(
            dict(
                cb=dtx_message_header_struct.sizeof(),
                fragmentId=0,
                fragmentCount=1,
                length=dtx_message_payload_header_struct.sizeof(),
                identifier=cur_message,
                conversationIndex=1,
                channelCode=chan,
                expectsReply=int(0),
            )
        )
        msg = mheader + pheader
        dvt.service.sendall(msg)

    def init_process_control(self):
        dvt_proxy = DvtSecureSocketProxyService(lockdown=self.service_provider)
        dvt_proxy.perform_handshake()
        return ProcessControl(dvt_proxy)
    

    def init_connection(self):
        dvt1 = DvtTestmanagedProxyService(lockdown=self.rsd)
        dvt1.perform_handshake()

        dvt2 = DvtTestmanagedProxyService(lockdown=self.rsd)
        dvt2.perform_handshake()

        return dvt1,dvt2


    def start_channel_with_capabilities(self, session_identifier: NSUUID, dvt: DvtTestmanagedProxyService, capabilities: dict):
        logger.info("make channel %s", self.IDENTIFIER)
        chan1 = dvt.make_channel(self.IDENTIFIER)
        # need prepare a response

        dvt.send_message(
                chan1,
                "_IDE_initiateSessionWithIdentifier:capabilities:",
                MessageAux().append_obj(session_identifier)
                .append_obj(capabilities),
            )
        reply = chan1.receive_plist()
        logger.info("start_channel_with_capabilities replay n: %s", reply)
        # check the result return the XCTCapabilities
        return chan1
    
    def start_channel_with_cap(self, dvt: DvtTestmanagedProxyService,capabilities: dict):
        logger.info("make channel %s", self.IDENTIFIER)
        chan = dvt.make_channel(self.IDENTIFIER)
        # need prepare a response

        dvt.send_message(
                chan,
                "_IDE_initiateControlSessionWithCapabilities:",
                MessageAux().append_obj(capabilities),
            )
        reply = chan.receive_plist()
        logger.info("start_channel_with_cap replay n: %s", reply)
        # check the result return the XCTCapabilities
        return chan

    def start_channel_with_XCTestManager_IDEInterface(self, dvt: DvtTestmanagedProxyService,identify: str):
        logger.info("make channel %s", identify)
        chan1 = dvt.make_channel(identify) #dtxproxy:XCTestDriverInterface:XCTestManager_IDEInterface
        # need prepare a response

        # dvt.send_message(
        #         chan1,
        #         "_IDE_initiateSessionWithIdentifier:capabilities:",
        #         MessageAux().append_obj(dvt)
        #         .append_obj(capabilities),
        #     )
        # reply = chan1.receive_plist()
        # logger.info("conn1 handshake xcode version: %s", reply)
        # returnValue = reply.Payload[0]
        return chan1



    def start_channels2(self, session_identifier: NSUUID,dvt1: DvtTestmanagedProxyService):
        logger.info("make channel %s", self.IDENTIFIER)
        chan1 = dvt1.make_channel(self.IDENTIFIER)
        # need prepare a response

    def init_ide_channels(self, session_identifier: NSUUID,dvt1: DvtTestmanagedProxyService):
        # XcodeIDE require two connections
        dvt1 = DvtTestmanagedProxyService(lockdown=self.service_provider)
        dvt1.perform_handshake()

        logger.info("make channel %s", self.IDENTIFIER)
        chan1 = dvt1.make_channel(self.IDENTIFIER)
        if self.product_major_version >= 11:
            dvt1.send_message(
                chan1,
                "_IDE_initiateControlSessionWithProtocolVersion:",
                MessageAux().append_obj(self.XCODE_VERSION),
            )
            reply = chan1.receive_plist()
            logger.info("conn1 handshake xcode version: %s", reply)

       
        chan2 = dvt2.make_channel(self.IDENTIFIER)
        dvt2.send_message(
            channel=chan2,
            selector="_IDE_initiateSessionWithIdentifier:forClient:atPath:protocolVersion:",
            args=MessageAux()
            .append_obj(session_identifier)
            .append_obj("not-very-import-part")  # this part is not important
            .append_obj("/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild")
            .append_obj(self.XCODE_VERSION),
        )
        reply = chan2.receive_plist()
        logger.info("conn2 handshake xcode version: %s", reply)
        return dvt1, chan1, dvt2, chan2

    def setup_xcuitest(
        self,
        bundle_id: str,
        xctest_path: str,
        xctest_configuration: XCTestConfiguration,
    ):
        """push xctestconfiguration to app VendDocuments"""
        with HouseArrestService(
            lockdown=self.service_provider, bundle_id=bundle_id, documents_only=False
        ) as afc:
            for name in afc.listdir("/tmp"):
                if name.endswith(".xctestconfiguration"):
                    logger.debug("remove /tmp/%s", name)
                    afc.rm("/tmp/" + name)
            afc.set_file_contents(xctest_path, archiver.archive(xctest_configuration))

    def start_executing_test_plan_with_protocol_version(self, dvt: DvtTestmanagedProxyService, protocol_version: int,channel: Channel):
        # ide_channel = Channel.create(-1, dvt)
        # dvt.channel_messages[ide_channel] = ChannelFragmenter()
        dvt.send_message(
            channel,
            "_IDE_startExecutingTestPlanWithProtocolVersion:",
            MessageAux().append_obj(protocol_version),
            expects_reply=False,
        )

    def authorize_test_process_id(self, chan: Channel, pid: int):
        aux = MessageAux()
        selector = "_IDE_authorizeTestSessionWithProcessID:"
        aux.append_obj(pid)
        chan.send_message(selector, aux)
        reply = chan.receive_plist()
        if isinstance(reply, bool) and reply is True:
            logger.info("authorizing test session for pid %d successful %r", pid, reply)
        else:
            raise RuntimeError("Failed to authorize test process id: %s" % reply)

    async def launch_test_app17(
        self,
        app_info: dict,
        bundle_id: str,
        test_runner_env: Optional[dict] = None,
        test_runner_args: Optional[list] = None,
        sessionId: NSUUID = None,
    ) -> int:
        app_container = app_info["Container"]
        app_path = app_info["Path"]
        exec_name = app_info["CFBundleExecutable"]
        # # logger.info('CFBundleExecutable: %s', exec_name)
        # # CFBundleName always endswith -Runner
        assert exec_name.endswith("-Runner"), (
            "Invalid CFBundleExecutable: %s" % exec_name
        )
        target_name = exec_name[: -len("-Runner")]

        app_env = {
            "CA_ASSERT_MAIN_THREAD_TRANSACTIONS": "0",
            "CA_DEBUG_TRANSACTIONS": "0",
            "DYLD_FRAMEWORK_PATH": app_path + "/Frameworks:",
            "DYLD_LIBRARY_PATH": app_path + "/Frameworks",
            "MTC_CRASH_ON_REPORT": "1",
            "NSUnbufferedIO": "YES",
            "SQLITE_ENABLE_THREAD_ASSERTIONS": "1",
            "WDA_PRODUCT_BUNDLE_IDENTIFIER": "",
            "XCTestBundlePath": f'{app_info["Path"]}/PlugIns/{target_name}.xctest',
            # "XCTestConfigurationFilePath": "",
            "XCODE_DBG_XPC_EXCLUSIONS": "com.apple.dt.xctestSymbolicator",
            # the following maybe no needed
            # 'MJPEG_SERVER_PORT': '',
            # 'USE_PORT': '',
            # 'LLVM_PROFILE_FILE': app_container + '/tmp/%p.profraw', # %p means pid
        }
        if test_runner_env:
            app_env.update(test_runner_env)

        if self.product_major_version >= 11:
            app_env[
                "DYLD_INSERT_LIBRARIES"
            ] = "/Developer/usr/lib/libMainThreadChecker.dylib"
            app_env["OS_ACTIVITY_DT_MODE"] = "YES"

        app_args = [
            "-NSTreatUnknownArgumentsAsOpen",
            "NO",
            "-ApplePersistenceIgnoreState",
            "YES",
        ]
        app_args.extend(test_runner_args or [])
        app_options = {"StartSuspendedKey": False}
        if self.product_major_version >= 12:
            app_options["ActivateSuspended"] = True


        openstdioSocket = Openstdiosocket(self.rsd)
        io_uuid = openstdioSocket.get_uuid()
        print("get the std uuid = " + str(io_uuid))

        async with AppServiceService(self.service_provider) as app_service:
            sessioinIdUP = str(uuid.UUID(bytes=sessionId.bytes)).upper()
            re = await app_service.test_launch_application2(sessioinIdUP, stdID=io_uuid)
            pid = int(re["processToken"]["processIdentifier"])
            print("pid:", pid)

        return pid


def get_app_info(service_provider: LockdownClient, bundle_id: str) -> Mapping[str, Any]:
    with InstallationProxyService(lockdown=service_provider) as install_service:
        apps = install_service.get_apps(bundle_identifiers=[bundle_id])
        if not apps:
            raise AppNotInstalledError(f"No app with bundle id {bundle_id} found")
        return apps[bundle_id]


def generate_xctestconfiguration(
    app_info: dict,
    session_identifier: NSUUID,
    target_app_bundle_id: str = None,
    target_app_env: Optional[dict] = None,
    target_app_args: Optional[list] = None,
    tests_to_run: Optional[list] = None,
) -> XCTestConfiguration:
    exec_name: str = app_info["CFBundleExecutable"]
    assert exec_name.endswith("-Runner"), "Invalid CFBundleExecutable: %s" % exec_name
    config_name = exec_name[: -len("-Runner")]
    _path = app_info["Path"]
    _bundleName = app_info["CFBundleName"]
    _bundleId = app_info["CFBundleIdentifier"]
    _home = app_info["EnvironmentVariables"]["HOME"]

    return XCTestConfiguration(
        {
            "targetApplicationPath": _path,
            "testBundleURL": NSURL(
                None, f'PlugIns/WebDriverAgentRunner.xctest'
            ),
            "sessionIdentifier": session_identifier,
            "targetApplicationBundleID": target_app_bundle_id,
            "targetApplicationEnvironment": target_app_env or {},
            "targetApplicationArguments": target_app_args or [],
            "testsToRun": tests_to_run or set(),
            "testsMustRunOnMainThread": True,
            "reportResultsToIDE": True,
            "reportActivities": True,
            "automationFrameworkPath": "/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework",
        }
    )
