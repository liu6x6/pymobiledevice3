import socket
from typing import Generator, Mapping, Union

from pymobiledevice3.exceptions import NotificationTimeoutError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.lockdown_service import LockdownService


class RemoteTrustedService(LockdownService):
    SERVICE_NAME = 'com.apple.mobile.notification_proxy'
    RSD_SERVICE_NAME = 'com.apple.mobile.lockdown.remote.trusted'

    INSECURE_SERVICE_NAME = 'com.apple.mobile.insecure_notification_proxy'
    RSD_INSECURE_SERVICE_NAME = 'com.apple.mobile.insecure_notification_proxy.shim.remote'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, RemoteServiceDiscoveryService):
            service_name = self.RSD_SERVICE_NAME
        else:
            service_name = self.SERVICE_NAME

        super().__init__(lockdown, service_name)