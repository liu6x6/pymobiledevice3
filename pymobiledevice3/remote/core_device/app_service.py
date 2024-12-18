import plistlib
from typing import Optional

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type
from pymobiledevice3.exceptions import CoreDeviceError

import uuid

class AppServiceService(CoreDeviceService):
    """
    Manage applications
    """

    SERVICE_NAME = 'com.apple.coredevice.appservice'

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def list_apps(self, include_app_clips: bool = True, include_removable_apps: bool = True,
                        include_hidden_apps: bool = True, include_internal_apps: bool = True,
                        include_default_apps: bool = True) -> list[dict]:
        """ List applications """
        return await self.invoke('com.apple.coredevice.feature.listapps', {
            'includeAppClips': include_app_clips, 'includeRemovableApps': include_removable_apps,
            'includeHiddenApps': include_hidden_apps, 'includeInternalApps': include_internal_apps,
            'includeDefaultApps': include_default_apps})

    async def launch_application(
            self, bundle_id: str, arguments: Optional[list[str]] = None, kill_existing: bool = True,
            start_suspended: bool = False, environment: Optional[dict] = None, extra_options: Optional[dict] = None) \
            -> list[dict]:
        """ launch application """
        return await self.invoke('com.apple.coredevice.feature.launchapplication', {
            'applicationSpecifier': {
                'bundleIdentifier': {'_0': bundle_id},
            },
            'options': {
                'arguments': arguments if arguments is not None else [],
                'environmentVariables': environment if environment is not None else {},
                'standardIOUsesPseudoterminals': True,
                'startStopped': start_suspended,
                'terminateExisting': kill_existing,
                'user': {'shortName': 'mobile'},
                'platformSpecificOptions': plistlib.dumps(extra_options if extra_options is not None else {}),
            },
            'standardIOIdentifiers': {
            },
        })

    async def list_processes(self) -> list[dict]:
        """ List processes """
        return (await self.invoke('com.apple.coredevice.feature.listprocesses'))['processTokens']

    async def list_roots(self) -> dict:
        """
        List roots.

        Can only be performed on certain devices
        """
        return await self.invoke('com.apple.coredevice.feature.listroots', {
            'rootPoint': {
                'relative': '/'
            }})

    async def spawn_executable(self, executable: str, arguments: list[str]) -> dict:
        """
        Spawn given executable.

        Can only be performed on certain devices
        """
        return await self.invoke('com.apple.coredevice.feature.spawnexecutable', {
            'executableItem': {
                'url': {
                    '_0': {
                        'relative': executable,
                    },
                }
            },
            'standardIOIdentifiers': {},
            'options': {
                'arguments': arguments,
                'environmentVariables': {},
                'standardIOUsesPseudoterminals': True,
                'startStopped': False,
                'user': {
                    'active': True,
                },
                'platformSpecificOptions': plistlib.dumps({}),
            },
        })

    async def monitor_process_termination(self, pid: int) -> dict:
        """
        Monitor process termination.

        Can only be performed on certain devices
        """
        return await self.invoke('com.apple.coredevice.feature.monitorprocesstermination', {
            'processToken': {'processIdentifier': XpcInt64Type(pid)}})

    async def uninstall_app(self, bundle_identifier: str) -> None:
        """
        Uninstall given application by its bundle identifier
        """
        await self.invoke('com.apple.coredevice.feature.uninstallapp', {'bundleIdentifier': bundle_identifier})

    async def send_signal_to_process(self, pid: int, signal: int) -> dict:
        """
        Send signal to given process by its pid
        """
        return await self.invoke('com.apple.coredevice.feature.sendsignaltoprocess', {
            'process': {'processIdentifier': XpcInt64Type(pid)},
            'signal': XpcInt64Type(signal),
        })

    async def fetch_icons(self, bundle_identifier: str, width: float, height: float, scale: float,
                          allow_placeholder: bool) -> dict:
        """
        Fetch given application's icons
        """
        return await self.invoke('com.apple.coredevice.feature.fetchappicons', {
            'width': width,
            'height': height,
            'scale': scale,
            'allowPlaceholder': allow_placeholder,
            'bundleIdentifier': bundle_identifier
        })
    
    def launch_application6(self) -> Mapping:
        input1 =  {
                    "applicationSpecifier": {
                        "bundleIdentifier": {
                            "_0": "com.apple.test.WebDriverAgentRunner-Runner"
                        }
                    },
                    "options": {
                        "arguments": [],
                        "environmentVariables": {
                            "CA_ASSERT_MAIN_THREAD_TRANSACTIONS": "0",
                            "CA_DEBUG_TRANSACTIONS": "0",
                            "DYLD_FRAMEWORK_PATH": "/System/Developer/Library/Frameworks",
                            "DYLD_LIBRARY_PATH": "/System/Developer/usr/lib",
                            "LLVM_PROFILE_FILE": "/dev/null",
                            "NSUnbufferedIO": "YES",
                            "RUN_DESTINATION_DEVICE_ECID": "5076519073366046",
                            "RUN_DESTINATION_DEVICE_NAME": "CN090",
                            "RUN_DESTINATION_DEVICE_PLATFORM_IDENTIFIER": "com.apple.platform.iphoneos",
                            "RUN_DESTINATION_DEVICE_UDID": "00008110-001209113410401E",
                            "XCTestBundlePath": "PlugIns/WebDriverAgentRunner.xctest",
                            "XCTestConfigurationFilePath": "",
                            "XCTestManagerVariant": "DDI",
                            "XCTestSessionIdentifier": "2D9F56CF-F53A-4638-B527-B4864F56BDB1",
                            "__XPC_LLVM_PROFILE_FILE": "/dev/null"
                        },
                        "installationResult": {
                            "_persistentIdentifier": ( b'\x00\x00\x00\x00'
                                                        b'\x08\x00\x00\x00'
                                                        b'\r-SE'
                                                        b'b\xf5A\x08'
                                                        b'\x95"^ '
                                                        b'\x9b\xd7\x85\xfc'
                                                        b'8\x05\x00\x00'
                                                        b'\x00\x00\x00\x00'),
                            "applicationBundleId": "com.apple.test.WebDriverAgentRunner-Runner",
                            "databaseSequenceNumber": XpcUInt64Type(2648),
                            "databaseUUID": uuid.UUID(hex="62cc4acd-f50b-455e-9c3b-cffc8254609f".replace("-","")),
                            "installationURL": {
                                "relative": "file:///private/var/containers/Bundle/Application/B8ECB7D6-DF9B-4B44-A812-FEE08D53BED5/WebDriverAgentRunner-Runner.app/"
                            }
                        },
                        "platformSpecificOptions": 
                                                    (b'bplist00'
                                                    b'\xd1\x01\x02_'
                                                    b'\x10\x13__Acti'
                                                    b'vateSuspende'
                                                    b'd\t\x08\x0b'
                                                    b'!\x00\x00\x00'
                                                    b'\x00\x00\x00\x01'
                                                    b'\x01\x00\x00\x00'
                                                    b'\x00\x00\x00\x00'
                                                    b'\x03\x00\x00\x00'
                                                    b'\x00\x00\x00\x00'
                                                    b'\x00\x00\x00\x00'
                                                    b'\x00\x00\x00\x00'
                                                    b'"'),
                        "standardIOUsesPseudoterminals": True,
                        "startStopped": True,
                        "terminateExisting": True,
                        "terminationHandler": {
                            "sideChannel": uuid.UUID(hex="2f196902-658f-4e89-b8a8-35db1024dca0".replace("-","")),
                        },
                        "user": {
                            "active": True
                        },
                        "workingDirectory": None
                    },
                    "standardIOIdentifiers": {
                        "standardError": uuid.UUID(hex="55a2b578-db25-4887-b5eb-2abc17cc9f90".replace("-","")),
                        "standardInput": uuid.UUID(hex="55a2b578-db25-4887-b5eb-2abc17cc9f90".replace("-","")),
                        "standardOutput": uuid.UUID(hex="55a2b578-db25-4887-b5eb-2abc17cc9f90".replace("-","")),
                    }
                }

        return self.invoke('com.apple.coredevice.feature.launchapplication', input1)  


    def test_launch_application(self, installResult: dict, sessionId: str, io_uuid: uuid) -> Mapping:
        sessionIdentifier = sessionId
        sideChannel = uuid.uuid4()
        DBSequence = XpcUInt64Type(installResult["DBSequence"])
        DBUUID = uuid.UUID(installResult["DBUUID"])
        applicationBundleId = "com.apple.test.WebDriverAgentRunner-Runner"
        PersistentIdentifier = installResult["PersistentIdentifier"]
        installationURL = installResult["InstallPath"]["com.apple.CFURL.string"]
        deviceIdentifier = "2070E331-97DE-429F-8D90-83133BE11FF2"
        dic = {
                "CoreDevice.CoreDeviceDDIProtocolVersion": XpcInt64Type(0),
                "CoreDevice.action": {},
                "CoreDevice.coreDeviceVersion": {
                    "components": [
                        XpcUInt64Type(348),
                        XpcUInt64Type(1),
                        XpcUInt64Type(0),
                        XpcUInt64Type(0),
                        XpcUInt64Type(0)
                    ],
                    "originalComponentsCount": XpcInt64Type(2),
                    "stringValue": "348.1"  #copyDevice 的result里有
                },
                "CoreDevice.deviceIdentifier": deviceIdentifier,
                "CoreDevice.featureIdentifier": "com.apple.coredevice.feature.launchapplication",
                "CoreDevice.input": {
                    "applicationSpecifier": {
                        "bundleIdentifier": {
                            "_0": "com.apple.test.WebDriverAgentRunner-Runner"
                        }
                    },
                    "options": {
                        "arguments": [],
                        "environmentVariables": {
                            "CA_ASSERT_MAIN_THREAD_TRANSACTIONS": "0",
                            "CA_DEBUG_TRANSACTIONS": "0",
                            "DYLD_FRAMEWORK_PATH": "/System/Developer/Library/Frameworks",
                            "DYLD_LIBRARY_PATH": "/System/Developer/usr/lib",
                            "LLVM_PROFILE_FILE": "/dev/null",
                            "NSUnbufferedIO": "YES",
                            "RUN_DESTINATION_DEVICE_ECID": "5076519073366046",
                            "RUN_DESTINATION_DEVICE_NAME": "CN090",
                            "RUN_DESTINATION_DEVICE_PLATFORM_IDENTIFIER": "com.apple.platform.iphoneos",
                            "RUN_DESTINATION_DEVICE_UDID": "00008110-001209113410401E",
                            "XCTestBundlePath": "PlugIns/WebDriverAgentRunner.xctest",
                            "XCTestConfigurationFilePath": "",
                            "XCTestManagerVariant": "DDI",
                            "XCTestSessionIdentifier": sessionIdentifier, #
                            "__XPC_LLVM_PROFILE_FILE": "/dev/null",
                        },
                        "installationResult": {
                            "_persistentIdentifier": PersistentIdentifier,
                            "applicationBundleId": applicationBundleId,
                            "databaseSequenceNumber": DBSequence,
                            "databaseUUID": DBUUID,
                            "installationURL": {"relative": installationURL}
                        },
                        "platformSpecificOptions": (b'bplist00'
                                                    b'\xd1\x01\x02_'
                                                    b'\x10\x13__Acti'
                                                    b'vateSuspende'
                                                    b'd\t\x08\x0b'
                                                    b'!\x00\x00\x00'
                                                    b'\x00\x00\x00\x01'
                                                    b'\x01\x00\x00\x00'
                                                    b'\x00\x00\x00\x00'
                                                    b'\x03\x00\x00\x00'
                                                    b'\x00\x00\x00\x00'
                                                    b'\x00\x00\x00\x00'
                                                    b'\x00\x00\x00\x00'
                                                    b'"'),
                        "standardIOUsesPseudoterminals": True,
                        "startStopped": True,
                        "terminateExisting": True,
                        "terminationHandler": {
                            "sideChannel": sideChannel  #这个又是什么
                        },
                        "user": {
                            "active": True
                        },
                        "workingDirectory": None
                    },
                    "standardIOIdentifiers": {
                        "standardError": io_uuid,
                        "standardInput": io_uuid,
                        "standardOutput": io_uuid
                    }
                },
                "CoreDevice.invocationIdentifier": str(uuid.uuid4())  ##这个又是什么
            }
        response = self.service.send_receive_request(dic)
        output = response.get('CoreDevice.output')
        if output is None:
            raise CoreDeviceError(f'Failed to invoke: com.apple.coredevice.feature.launchapplication. Got error: {response}')
        return output
    

    async def test_launch_application2(self, sessionIdentifier: str, stdID: uuid, XCTestBundlePath: str) -> Mapping:

        ops = {
            "ActivateSuspended": 1,
		    "StartSuspendedKey": 0,
        }
        platformSpecificOptions = plistlib.dumps(ops, fmt=plistlib.FMT_BINARY)
        # build binary plist ops to platformSpecificOptions

        env = {
                "CA_ASSERT_MAIN_THREAD_TRANSACTIONS": "0",
                "CA_DEBUG_TRANSACTIONS": "0",
                "DYLD_FRAMEWORK_PATH": "/System/Developer/Library/Frameworks",
                "DYLD_LIBRARY_PATH": "/System/Developer/usr/lib",
                "DYLD_INSERT_LIBRARIES": "/Developer/usr/lib/libMainThreadChecker.dylib",
                "NSUnbufferedIO": "YES",
                "MTC_CRASH_ON_REPORT":             "1",
                "OS_ACTIVITY_DT_MODE":             "YES",
                "SQLITE_ENABLE_THREAD_ASSERTIONS": "1",
                "XCTestBundlePath": XCTestBundlePath,
                "XCTestConfigurationFilePath": "",
                "XCTestManagerVariant": "DDI",
                "XCTestSessionIdentifier": sessionIdentifier, #Upper case
                }
        
        _input = {
                    "applicationSpecifier": {
                        "bundleIdentifier": {
                            "_0": "com.apple.test.WebDriverAgentRunner-Runner"
                        }
                    },
                    "options": {
                        "arguments": [],
                        "environmentVariables":env,
                        "platformSpecificOptions": platformSpecificOptions,
                        "standardIOUsesPseudoterminals": True,
                        "startStopped": False,
                        "terminateExisting": True,
                        "user": {
                            "active": True
                        },
                        "workingDirectory": None
                    },
                    "standardIOIdentifiers": {
                        "standardError": stdID,
                        "standardInput": stdID,
                        "standardOutput": stdID
                    }
                }
        
        output = await self.invoke("com.apple.coredevice.feature.launchapplication", _input)
        return output

    def launch_application_raw(self,data: bytes) -> Mapping:
        return self.invoke_raw(data)

        deviceIdentifier = "2070E331-97DE-429F-8D90-83133BE11FF2"
        dic = {
            "CoreDevice.CoreDeviceDDIProtocolVersion": XpcInt64Type(0),
                "CoreDevice.action": {},
                "CoreDevice.coreDeviceVersion": {
                    "components": [
                        XpcUInt64Type(348),
                        XpcUInt64Type(1),
                        XpcUInt64Type(0),
                        XpcUInt64Type(0),
                        XpcUInt64Type(0)
                    ],
                    "originalComponentsCount": XpcInt64Type(2),
                    "stringValue": "348.1"  #copyDevice 的result里有
                },
                "CoreDevice.deviceIdentifier": deviceIdentifier,
                "CoreDevice.featureIdentifier": "com.apple.coredevice.feature.sendsignaltoprocess",
                "CoreDevice.input": {"process": {"processIdentifier": XpcInt64Type(pid)}, "signal": XpcInt64Type(19)},
                "CoreDevice.invocationIdentifier": str(uuid.uuid4())  ##这个又是什么
        }

        response = self.service.send_receive_request(dic)
        output = response.get('CoreDevice.output')
        if output is None:
            raise CoreDeviceError(f'Failed to invoke: com.apple.coredevice.feature.sendsignaltoprocess. Got error: {response}')
        return output
