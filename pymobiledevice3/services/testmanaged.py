#!/usr/bin/env python3
from typing import Union

from packaging.version import Version

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.remote_server import RemoteServer


class TestmanagerdService(RemoteServer):
    SERVICE_NAME = 'com.apple.instruments.remoteserver.DVTSecureSocketProxy'
    RSD_SERVICE_NAME = 'com.apple.dt.testmanagerd.remote'

    def __init__(self, lockdown: Union[RemoteServiceDiscoveryService, LockdownClient]):
        if isinstance(lockdown, RemoteServiceDiscoveryService):
            service_name = self.RSD_SERVICE_NAME
            remove_ssl_context = False
        else:
            service_name = self.SERVICE_NAME
            remove_ssl_context = False

        super().__init__(lockdown, service_name, remove_ssl_context=remove_ssl_context)
