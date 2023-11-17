import uuid
from typing import Any, Mapping

from pymobiledevice3.exceptions import CoreDeviceError
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type

import plistlib

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type



class BridgeService(RemoteService):
    SERVICE_NAME = 'com.apple.mobile.storage_mounter_proxy.bridge'

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)