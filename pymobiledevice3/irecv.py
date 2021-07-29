import usb.backend
from usb.core import find, Device
from usb._debug import methodtrace
import usb.util

IRECV_K_RECOVERY_MODE_1 = 0x1280
IRECV_K_RECOVERY_MODE_2 = 0x1281
IRECV_K_RECOVERY_MODE_3 = 0x1282
IRECV_K_RECOVERY_MODE_4 = 0x1283
IRECV_K_WTF_MODE = 0x1222
IRECV_K_DFU_MODE = 0x122

APPLE_VENDOR_ID = 0x05AC


class IRecv:
    def __init__(self):
        self._device = None  # type: Device
        self._device_info = {}
        self._find()
        self._populate_device_info()

    def _find(self):
        for device in find(find_all=True):
            if not device.manufacturer.startswith('Apple'):
                continue
            if 'Recovery Mode' not in device.product:
                continue
            if self._device is not None:
                raise Exception('More then one connected device was found connected in recovery mode')
            self._device = device

    def _populate_device_info(self):
        for component in self._device.serial_number.split(' '):
            k, v = component.split(':')
            if k == 'SRNM' and '[' in v:
                # trim the `[]`
                v = v[1:-1]
            self._device_info[k] = v

    def __str__(self):
        return str(self._device)


def main():
    print(IRecv())


if __name__ == '__main__':
    main()
