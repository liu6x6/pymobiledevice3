import zipfile
from io import BytesIO

from pymobiledevice3.lockdown import LockdownClient


class RestoreService:
    def __init__(self, lockdown: LockdownClient, ipsw: BytesIO):
        self._lockdown = lockdown
        ipsw = zipfile.ZipFile(ipsw)
        self._build

    def upgrade(self, filename):
        pass
