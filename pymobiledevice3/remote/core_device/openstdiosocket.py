from typing import List, Mapping
 
from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
import uuid
 
import socket
from socket import create_connection
from pymobiledevice3.exceptions import InvalidServiceError
import threading
 
 
class Openstdiosocket(CoreDeviceService):
    """
    get the std input output err uuid by just connect this server?
    this serever look like just a tcp socket
    no a normal rsd server or codedevice server
    """
 
    SERVICE_NAME = 'com.apple.coredevice.openstdiosocket'
    # io_uuid = null
 
    def __init__(self, rsd: RemoteServiceDiscoveryService):
        # super().__init__(rsd, self.SERVICE_NAME)
        self.rsd = rsd
        self.address = self.rsd.service.address[0]
        self.port = self.get_service_port(self.SERVICE_NAME)
       
        # response should be the uuid for lanchApplication
 
    def get_uuid(self) -> uuid:
        """
        Get device information
        """
 
        self.sock = create_connection((self.address,self.port))
        buf = self._recvall(16)
        print(buf)
        # create uuid from byte
        self.io_uuid = uuid.UUID(bytes=buf)
        return self.io_uuid
    
    def get_service_port(self, name: str) -> int:
        """takes a service name and returns the port that service is running on if the service exists"""
        service = self.rsd.peer_info['Services'].get(name)
        if service is None:
            raise InvalidServiceError(f'No such service: {name}')
        return int(service['Port'])
 
    def _recvall(self, size: int) -> bytes:
        data = b''
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if chunk is None or len(chunk) == 0:
                raise ConnectionAbortedError()
            data += chunk
        return data
    
    def loop_data(self):
        buffer = b''
        while True:
            try:
                # Try receiving data
                data = self.sock.recv(1024)
                if data:
                    buffer += data
                    if b'\n' in buffer:
                        messages = buffer.split(b'\n')
                        for message in messages[:-1]:
                            print(f"Received complete message: {message.decode('utf-8')}")
                        buffer = messages[-1]
                else:
                    # If recv() returns empty, the socket is closed
                    print("Client disconnected gracefully")
                    break
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                print("Socket connection broken")
                break
            except socket.error as e:
                print(f"Socket error: {e}")
                break
        

    def starting(self):
        #keep receive log
        receiving_thread = threading.Thread(target=self.loop_data)
        receiving_thread.start()

