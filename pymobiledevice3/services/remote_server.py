import copy
import io
import os
import plistlib
import typing
import uuid
from functools import partial
from pprint import pprint
from queue import Empty, Queue

import IPython
from bpylist2 import archiver
from bpylist2.archiver import ArchivedObject
from construct import Adapter, Const, Default, GreedyBytes, GreedyRange, Int16ul, Int32sl, Int32ul, Int64ul, Prefixed, \
    Select, Struct, Switch, this
from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import DvtException, UnrecognizedSelectorError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
import uuid
import pprint
SHELL_USAGE = '''
# This shell allows you to send messages to the DVTSecureSocketProxy and receive answers easily.
# Generally speaking, each channel represents a group of actions.
# Calling actions is done using a selector and auxiliary (parameters).
# Receiving answers is done by getting a return value and seldom auxiliary (private / extra parameters).
# To see the available channels, type the following:
developer.supported_identifiers

# In order to send messages, you need to create a channel:
channel = developer.make_channel('com.apple.instruments.server.services.deviceinfo')

# After creating the channel you can call allowed selectors:
channel.runningProcesses()

# If an answer is expected, you can receive it using the receive method:
processes = channel.receive_plist()

# You can also call methods from the broadcast channel
broadcast.someMethod()

# Sometimes the selector requires parameters, You can add them using MessageAux. For example lets kill a process:
channel = developer.make_channel('com.apple.instruments.server.services.processcontrol')
args = MessageAux().append_obj(80) # This will kill pid 80
channel.killPid_(args, expects_reply=False) # Killing a process doesn't require an answer.

# In some rare cases, you might want to receive the auxiliary and the selector return value.
# For that cases you can use the recv_plist method.
return_value, auxiliary = developer.recv_plist()
'''


class BplitAdapter(Adapter):
    def _decode(self, obj, context, path):
        return archiver.unarchive(obj)

    def _encode(self, obj, context, path):
        return archiver.archive(obj)


message_aux_t_struct = Struct(
    'magic' / Default(Int64ul, 0x1f0),
    'aux' / Prefixed(Int64ul, GreedyRange(Struct(
        '_empty_dictionary' / Select(Const(0xa, Int32ul), Int32ul),
        'type' / Int32ul,
        'value' / Switch(this.type, {2: BplitAdapter(Prefixed(Int32ul, GreedyBytes)), 3: Int32ul, 6: Int64ul},
                         default=GreedyBytes),
    )))
)
dtx_message_header_struct = Struct(
    'magic' / Const(0x1F3D5B79, Int32ul),
    'cb' / Int32ul,
    'fragmentId' / Int16ul,
    'fragmentCount' / Int16ul,
    'length' / Int32ul,
    'identifier' / Int32ul,
    'conversationIndex' / Int32ul,
    'channelCode' / Int32sl,
    'expectsReply' / Int32ul,
)
dtx_message_payload_header_struct = Struct(
    'flags' / Int32ul,
    'auxiliaryLength' / Int32ul,
    'totalLength' / Int64ul,
)


class MessageAux:
    def __init__(self):
        self.values = []

    def append_int(self, value: int):
        self.values.append({'type': 3, 'value': value})
        return self

    def append_long(self, value: int):
        self.values.append({'type': 6, 'value': value})
        return self

    def append_signed_int(self, value: int):
        """ 有符号 int """
        self.values.append({'type': 3, 'value': value})
        return self
    
    def append_signed_long(self, value: int):
        """ 有符号 long """
        self.values.append({'type': 6, 'value': value})
        return self

    def append_obj(self, value):
        self.values.append({'type': 2, 'value': value})
        return self

    def __bytes__(self):
        return message_aux_t_struct.build(dict(aux=self.values))


class XCTestConfiguration():
    @staticmethod
    def decode_archive(archive_obj):
        metadata_dict = {}
        for key, value in archive_obj.object.items():
            try:
                if key == "$class":
                    continue
                decoded_value = archive_obj.decode(key)
                metadata_dict[key] = decoded_value
            except Exception as e:
                print(e)
                pass
        return metadata_dict

class XCTRepetitionPolicy():
    @staticmethod
    def decode_archive(archive_obj):
        metadata_dict = {}
        for key, value in archive_obj.object.items():
            try:
                if key == "$class":
                    continue
                decoded_value = archive_obj.decode(key)
                metadata_dict[key] = decoded_value
            except Exception as e:
                print(e)
                pass
        return metadata_dict
    
class XCTRuntimeIssueDetectionPolicy():
    @staticmethod
    def decode_archive(archive_obj):
        metadata_dict = {}
        for key, value in archive_obj.object.items():
            try:
                if key == "$class":
                    continue
                decoded_value = archive_obj.decode(key)
                metadata_dict[key] = decoded_value
            except Exception as e:
                print(e)
                pass
        return metadata_dict

class XCTCapabilities():
    @staticmethod
    def decode_archive(archive_obj):
        # obj = archive_obj.decode('capabilities-dictionary')
        # return obj
        metadata_dict = {}
        for key, value in archive_obj.object.items():
            try:
                if key == "$class":
                    continue
                decoded_value = archive_obj.decode(key)
                metadata_dict[key] = decoded_value
            except Exception as e:
                print(e)
                pass
        return metadata_dict
    
class DTTapMessage:
    @staticmethod
    def decode_archive(archive_obj):
        return archive_obj.decode('DTTapMessagePlist')

class XCTAttachmentFutureMetadata:
    @staticmethod
    def decode_archive(archive_obj):
        metadata_dict = {}
        for key, value in archive_obj.object.items():
            try:
                if key == "$class":
                    continue
                decoded_value = archive_obj.decode(key)
                metadata_dict[key] = decoded_value
            except Exception as e:
                print(e)
                pass
        return metadata_dict

class NSURL:
    @staticmethod
    def decode_archive(archive_obj):
        base_url = archive_obj.decode('NS.base')
        relative_url = archive_obj.decode('NS.relative')
        # Combine the base and relative URLs
        url = (base_url or '') + (relative_url or '')
        return url


class NSNull:
    @staticmethod
    def decode_archive(archive_obj):
        return None


class NSError:
    @staticmethod
    def encode_archive(archive_obj):
        return archiver.archive(archive_obj)

    @staticmethod
    def decode_archive(archive_obj):
        user_info = archive_obj.decode('NSUserInfo')
        if user_info.get('NSLocalizedDescription', '').endswith(' - it does not respond to the selector'):
            raise Exception(user_info)
        raise Exception(archive_obj.decode('NSUserInfo'))
    
class NSUUID(uuid.UUID):
    @staticmethod
    def decode_archive(archive_obj):
        my_uuid = uuid.UUID(bytes=archive_obj.object["NS.uuidbytes"])
        return my_uuid
    
    @staticmethod
    def encode_archive(objects, archive):
        archive._archive_obj["NS.uuidbytes"] = objects.bytes



class NSUUID(uuid.UUID):
    @staticmethod
    def uuid4():
        """Generate a random UUID."""
        return NSUUID(bytes=os.urandom(16))

    def encode_archive(self, archive_obj: archiver.ArchivingObject):
        archive_obj.encode('NS.uuidbytes', self.bytes)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return NSUUID(bytes=archive_obj.decode('NS.uuidbytes'))


class NSURL:
    def __init__(self, base, relative):
        self.base = base
        self.relative = relative

    def encode_archive(self, archive_obj: archiver.ArchivingObject):
        archive_obj.encode('NS.base', self.base)
        archive_obj.encode('NS.relative', self.relative)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return NSURL(archive_obj.decode('NS.base'), archive_obj.decode('NS.relative'))


class NSValue:
    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return archive_obj.decode('NS.rectval')


class NSMutableData:
    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return archive_obj.decode('NS.data')


class NSMutableString:
    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return archive_obj.decode('NS.string')


class XCTestConfiguration:
    _default = {
        # 'testBundleURL': UID(3),
        # 'sessionIdentifier': UID(8), # UUID
        'aggregateStatisticsBeforeCrash': {
            'XCSuiteRecordsKey': {}
        },
        'automationFrameworkPath': '/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework',
        'baselineFileRelativePath': None,
        'baselineFileURL': None,
        'defaultTestExecutionTimeAllowance': None,
        'disablePerformanceMetrics': False,
        'emitOSLogs': False,
        'formatVersion': plistlib.UID(2),  # store in UID
        'gatherLocalizableStringsData': False,
        'initializeForUITesting': True,
        'maximumTestExecutionTimeAllowance': None,
        'productModuleName': 'WebDriverAgentRunner',  # set to other value is also OK
        'randomExecutionOrderingSeed': None,
        'reportActivities': True,
        'reportResultsToIDE': True,
        'systemAttachmentLifetime': 2,
        'targetApplicationArguments': [],  # maybe useless
        'targetApplicationBundleID': None,
        'targetApplicationEnvironment': None,
        'targetApplicationPath': '/whatever-it-does-not-matter/but-should-not-be-empty',
        'testApplicationDependencies': {},
        'testApplicationUserOverrides': None,
        'testBundleRelativePath': None,
        'testExecutionOrdering': 0,
        'testTimeoutsEnabled': False,
        'testsDrivenByIDE': False,
        'testsMustRunOnMainThread': True,
        'testsToRun': None,
        'testsToSkip': None,
        'treatMissingBaselinesAsFailures': False,
        'userAttachmentLifetime': 1
    }

    def __init__(self, kv: dict):
        assert 'testBundleURL' in kv
        assert 'sessionIdentifier' in kv
        self._config = copy.deepcopy(self._default)
        self._config.update(kv)

    def encode_archive(self, archive_obj: archiver.ArchivingObject):
        for k, v in self._config.items():
            archive_obj.encode(k, v)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return archive_obj.object


archiver.update_class_map({'DTSysmonTapMessage': DTTapMessage,
                           'DTTapHeartbeatMessage': DTTapMessage,
                           'DTTapStatusMessage': DTTapMessage,
                           'DTKTraceTapMessage': DTTapMessage,
                           'DTActivityTraceTapMessage': DTTapMessage,
                           'DTTapMessage': DTTapMessage,
                           'NSNull': NSNull,
                           'NSError': NSError,
                           'NSUUID': NSUUID,
                           'NSURL': NSURL,
                           'XCTCapabilities': XCTCapabilities,
                           "NSSet": set,
                           'XCTAttachmentFutureMetadata': XCTAttachmentFutureMetadata,
                           'XCTRepetitionPolicy': XCTRepetitionPolicy,
                           'XCTRuntimeIssueDetectionPolicy': XCTRuntimeIssueDetectionPolicy,
                           'NSValue': NSValue,
                           'NSMutableData': NSMutableData,
                           'NSMutableString': NSMutableString,
                           'XCTestConfiguration': XCTestConfiguration})

archiver.Archive.inline_types = list(set(archiver.Archive.inline_types + [bytes]))


class Channel(int):
    @classmethod
    def create(cls, value: int, service: 'RemoteServer'):
        channel = cls(value)
        channel._service = service
        return channel

    def receive_key_value(self):
        return self._service.recv_plist(self)

    def receive_plist(self):
        return self._service.recv_plist(self)[0]

    def receive_message(self):
        return self._service.recv_message(self)[0]

    def send_message(self, selector: str, args: MessageAux = None, expects_reply: bool = True):
        self._service.send_message(self, selector, args, expects_reply=expects_reply)

    @staticmethod
    def _sanitize_name(name: str):
        """
        Sanitize python name to ObjectiveC name.
        """
        if name.startswith('_'):
            name = '_' + name[1:].replace('_', ':')
        else:
            name = name.replace('_', ':')
        return name

    def __getitem__(self, item):
        return partial(self._service.send_message, self, item)

    def __getattr__(self, item):
        return self[self._sanitize_name(item)]


class ChannelFragmenter:
    def __init__(self):
        self._messages = Queue()
        self._packet_data = b''
        self._stream_packet_data = b''

    def get(self):
        return self._messages.get_nowait()

    def add_fragment(self, mheader, chunk):
        if mheader.channelCode >= 0:
            self._packet_data += chunk
            if mheader.fragmentId == mheader.fragmentCount - 1:
                # last message
                self._messages.put(self._packet_data)
                self._packet_data = b''
        else:
            self._stream_packet_data += chunk
            if mheader.fragmentId == mheader.fragmentCount - 1:
                # last message
                self._messages.put(self._stream_packet_data)
                self._stream_packet_data = b''


class RemoteServer(LockdownService):
    """
    Wrapper to Apple's RemoteServer.
    This server exports several ObjC objects allowing calling their respective selectors.
    The `/Developer/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DTServiceHub` service reads the
    configuration stored from `[[NSUserDefaults standardUserDefaults] boolForKey:@"DTXConnectionTracer"]`
    If the value is true, then `/tmp/DTServiceHub[PID].DTXConnection.RANDOM.log` is created and can be used to debug the
    transport protocol.

    For example:

    ```
    root@iPhone (/var/root)# tail -f /tmp/DTServiceHub[369].DTXConnection.qNjM2U.log
    170.887982 x4 resuming [c0]: <DTXConnection 0x100d20670 : x4>
    170.889120 x4   sent   [c0]: < DTXMessage 0x100d52b10 : i2.0 c0 dispatch:[_notifyOfPublishedCapabilities:<NSDictionary 0x100d0e1b0 | 92 key/value pairs>] >
    170.889547 x4 received [c0]: < DTXMessage 0x100d0a550 : i1.0 c0 dispatch:[_notifyOfPublishedCapabilities:<NSDictionary 0x100d16a40 | 2 key/value pairs>] >
    170.892101 x4 received [c0]: < DTXMessage 0x100d0a550 : i3.0e c0 dispatch:[_requestChannelWithCode:[1]identifier :"com.apple.instruments.server.services.deviceinfo"] >
    170.892238 x4   sent   [c0]: < DTXMessage 0x100d61830 : i3.1 c0 >
    170.892973 x4 received [c1f]: < DTXMessage 0x100d0a550 : i4.0e c1 dispatch:[runningProcesses] >
    171.204957 x4   sent   [c1f]: < DTXMessage 0x100c557a0 : i4.1 c1 object:(__NSArrayM*)<NSArray 0x100c199d0 | 245 objects> { <NSDictionary 0x100c167c0 | 5 key/value pairs>, <NSDictionary 0x100d17970 | 5 key/value pairs>, <NSDictionary 0x100d17f40 | 5 key/value pairs>, <NSDictionary 0x100d61750 | 5 key/value pairs>, <NSDictionary 0x100c16760 | 5 key/value pairs>, ...  } >
    171.213326 x4 received [c0]: < DTXMessage : kDTXInterruptionMessage >
    171.213424 x4  handler [c0]: < DTXMessage : i1 kDTXInterruptionMessage >
    171.213477 x4 received [c1f]: < DTXMessage : kDTXInterruptionMessage >
    ```

    For editing the configuration we can simply add the respected key into:
    `/var/mobile/Library/Preferences/.GlobalPreferences.plist` and kill `cfprefsd`

    The valid selectors for triggering can be found using the following Frida script the same way Troy Bowman used for
    iterating all classes which implement the protocol `DTXAllowedRPC`:

    ```shell
    frida -U DTServiceHub
    ```

    ```javascript
    for (var name in ObjC.protocols) {
        var protocol = ObjC.protocols[name]
        if ('DTXAllowedRPC' in protocol.protocols) {
            console.log('@protocol', name)
            console.log('  ' + Object.keys(protocol.methods).join('\n  '))
        }
    }
    ```
    """  # noqa: E501
    BROADCAST_CHANNEL = 0
    INSTRUMENTS_MESSAGE_TYPE = 2
    EXPECTS_REPLY_MASK = 0x1000

    def __init__(self, lockdown: LockdownServiceProvider, service_name, remove_ssl_context: bool = True,
                 is_developer_service: bool = True):
        super().__init__(lockdown, service_name, is_developer_service=is_developer_service)

        if remove_ssl_context and hasattr(self.service.socket, '_sslobj'):
            self.service.socket._sslobj = None

        self.supported_identifiers = {}
        self.last_channel_code = 0
        self.cur_message = 0
        self.channel_cache = {}
        self.channel_messages = {self.BROADCAST_CHANNEL: ChannelFragmenter()}
        self.broadcast = Channel.create(0, self)

    def shell(self):
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
            user_ns={
                'developer': self,
                'broadcast': self.broadcast,
                'MessageAux': MessageAux,
            })

    def perform_handshake(self):
        self.cur_message = 0
        args = MessageAux()
        args.append_obj({'com.apple.private.DTXBlockCompression': 2, 'com.apple.private.DTXConnection': 1})
        self.send_message(0, '_notifyOfPublishedCapabilities:', args, expects_reply=False)
        ret, aux = self.recv_plist()
        if ret != '_notifyOfPublishedCapabilities:':
            raise ValueError('Invalid answer')
        if not len(aux[0]):
            raise ValueError('Invalid answer')
        self.supported_identifiers = aux[0].value

    def make_channel(self, identifier) -> Channel:
        # NOTE: There is also identifier not in self.supported_identifiers
        # assert identifier in self.supported_identifiers
        if identifier in self.channel_cache:
            return self.channel_cache[identifier]

        self.last_channel_code += 1
        code = self.last_channel_code
        args = MessageAux().append_int(code).append_obj(identifier)
        self.send_message(0, '_requestChannelWithCode:identifier:', args)
        ret, aux = self.recv_plist()
        assert ret is None
        channel = Channel.create(code, self)
        self.channel_cache[identifier] = channel
        self.channel_messages[code] = ChannelFragmenter()
        return channel

    def send_message(self, channel: int, selector: str = None, args: MessageAux = None, expects_reply: bool = True):
        self.cur_message += 1

        aux = bytes(args) if args is not None else b''
        sel = archiver.archive(selector) if selector is not None else b''
        flags = self.INSTRUMENTS_MESSAGE_TYPE
        # if expects_reply:
        #     flags |= self.EXPECTS_REPLY_MASK
        pheader = dtx_message_payload_header_struct.build(dict(flags=flags, auxiliaryLength=len(aux),
                                                               totalLength=len(aux) + len(sel)))
        mheader = dtx_message_header_struct.build(dict(
            cb=dtx_message_header_struct.sizeof(),
            fragmentId=0,
            fragmentCount=1,
            length=dtx_message_payload_header_struct.sizeof() + len(aux) + len(sel),
            identifier=self.cur_message,
            conversationIndex=0,
            channelCode=channel,
            expectsReply=int(expects_reply)
        ))
        print()
        print("sendMessage: ")
        print("selector: ", selector)
        print("aux: ", None if args is None else args.values)
        print("flags: ", flags)
        print()
        msg = mheader + pheader + aux + sel
        if selector == "_IDE_collectNewCrashReportsInDirectories:matchingProcessNames:":
            name = "/Users/xiao/session.bin"
            with open(name, 'wb') as file:
                file.write(msg)
                print("write _IDE_collectNewCrashReportsInDirectories:matchingProcessNames: message to: session.bin")
        self.service.sendall(msg)

    def recv_plist(self, channel: int = BROADCAST_CHANNEL):
        data, aux = self.recv_message(channel)
        if data is not None:
            try:
                data = archiver.unarchive(data)
            except archiver.MissingClassMapping as e:
                pprint(plistlib.loads(data))
                raise e
            except plistlib.InvalidFileException:
                self.logger.warning(f'got an invalid plist: {data[:40]}')
        print("recv_plist: ")
        print("data: ", data)
        print("aux: ", aux)
        return data, aux

    def recv_message(self, channel: int = BROADCAST_CHANNEL):
        packet_stream = self._recv_packet_fragments(channel)
        pheader = dtx_message_payload_header_struct.parse_stream(packet_stream)

        compression = (pheader.flags & 0xFF000) >> 12
        if compression:
            print("NotImplementedError('Compressed')")
            raise NotImplementedError('Compressed')

        if pheader.auxiliaryLength:
            aux = message_aux_t_struct.parse_stream(packet_stream).aux
        else:
            aux = None
        obj_size = pheader.totalLength - pheader.auxiliaryLength
        data = packet_stream.read(obj_size) if obj_size else None
        return data, aux

    def _recv_packet_fragments(self, channel: int = BROADCAST_CHANNEL):
        while True:
            try:
                # if we already have a message for this channel, just return it
                message = self.channel_messages[channel].get()
                return io.BytesIO(message)
            except Empty:
                # if no message exists for the given channel code, just keep waiting and receive new messages
                # until the waited message queue has at least one message
                data = self.service.recvall(dtx_message_header_struct.sizeof())
                mheader = dtx_message_header_struct.parse(data)
                print("mheader: ", mheader)

                # treat both as the negative and positive representation of the channel code in the response
                # the same when performing fragmentation
                received_channel_code = abs(mheader.channelCode)

                if received_channel_code not in self.channel_messages:
                    self.channel_messages[received_channel_code] = ChannelFragmenter()

                if not mheader.conversationIndex:
                    if mheader.identifier > self.cur_message:
                        self.cur_message = mheader.identifier

                if mheader.fragmentCount > 1 and mheader.fragmentId == 0:
                    # when reading multiple message fragments, the first fragment contains only a message header
                    continue

                self.channel_messages[received_channel_code].add_fragment(mheader, self.service.recvall(mheader.length))

    def __enter__(self):
        self.perform_handshake()
        return self

    def close(self):
        aux = MessageAux()
        codes = [code for code in self.channel_messages.keys() if code > 0]
        if codes:
            for code in codes:
                aux.append_int(code)
            try:
                self.send_message(self.BROADCAST_CHANNEL, '_channelCanceled:', aux, expects_reply=False)
            except OSError:
                # ignore: OSError: [Errno 9] Bad file descriptor
                pass
        super().close()


class Tap:
    def __init__(self, dvt, channel_name: str, config: typing.Mapping):
        self._dvt = dvt
        self._channel_name = channel_name
        self._config = config
        self.channel = None

    def __enter__(self):
        self.channel = self._dvt.make_channel(self._channel_name)
        self.channel.setConfig_(MessageAux().append_obj(self._config), expects_reply=False)
        self.channel.start(expects_reply=False)

        # first message is just kind of an ack
        self.channel.receive_plist()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.channel.clear(expects_reply=False)

    def __iter__(self):
        while True:
            for result in self.channel.receive_plist():
                yield result

from construct import ConstError, StreamError
import pprint
pp = pprint.PrettyPrinter()
def check_outbound_data():
    index = 0
    while index <= 1064:
        # direction = 'inbound'
        direction = 'outbound'
        name = '/Users/isan/runtest/packets/{}_{}.bin'.format(str(index).zfill(4), direction)
        try:
            with open(name, 'rb') as f:
                print(name)
                data = f.read()
                # load dtx_message_header_struct.sizeof() bytes from the data
                mheader = dtx_message_header_struct.parse(data)
                received_channel_code = abs(mheader.channelCode)
                print(received_channel_code)
                # print(fileName, '  succeed')
        except Exception as e:
            # print(e)
            # print(fileName, '  failed')
            pass
        index = index + 1

class ParseDTXHelper():
    previous_data = b''
    channelFragmenter = None

    out_previous_data = b''
    out_channelFragmenter = None
    inbounding = True
    def process_data(self, unitData):
        try:
            if len(unitData) < 32:
                print("data 不完整")
                self.previous_data = unitData
                return
            # read dtx_message_header_struct.sizeof() data from the unitData
            headerData = unitData[:dtx_message_header_struct.sizeof()]
            mheader = dtx_message_header_struct.parse(headerData)
            # print("mheader: ", mheader)
            if mheader.fragmentCount > 1 and mheader.fragmentId == 0:
                # when reading multiple message fragments, the first fragment contains only a message header
                print("mheader.fragmentCount > 1 and mheader.fragmentId == 0")
                return
            # read mheader.length bytes behind the header from the unitData
            fdata = unitData[dtx_message_header_struct.sizeof():dtx_message_header_struct.sizeof()+mheader.length]
            # print("fdata: ", len(fdata))
            if len(fdata) != mheader.length:
                print("data 不完整")
                self.previous_data = unitData
                return

            chanelFra = self.channelFragmenter if self.channelFragmenter else ChannelFragmenter()
            chanelFra.add_fragment(mheader, fdata)
            stream = io.BytesIO(chanelFra.get())
            pheader = dtx_message_payload_header_struct.parse_stream(stream)
            # print("pheader: ", pheader)
            compression = (pheader.flags & 0xFF000) >> 12
            if compression:
                print("NotImplementedError('Compressed')")
                # raise NotImplementedError('Compressed')

            if pheader.auxiliaryLength:
                aux_struct= message_aux_t_struct.parse_stream(stream)
                aux = aux_struct.aux
            else:
                aux = None
            
            # print("aux: ")
            # pp.pprint(aux)
            obj_size = pheader.totalLength - pheader.auxiliaryLength
            data = stream.read(obj_size) if obj_size else None
            
            if data is not None:
                if len(data) != obj_size:
                    print("data 不完整")
                    self.previous_data = unitData
                    return
                try:
                    data = archiver.unarchive(data)
                except archiver.MissingClassMapping as e:
                    print("archiver.MissingClassMapping")
                    result = plistlib.loads(data)
                    print("result: ", result)
                    print(e)
                    # raise e
                except plistlib.InvalidFileException:
                    print(f'got an invalid plist: {data[:40]}')
            # print("data:", data)
            self.printData(mheader,fdata,pheader,aux,data)
            self.previous_data = b''
            # check if there is any remaining data in unitData
            if len(unitData) > dtx_message_header_struct.sizeof()+mheader.length:
                remaining_data = unitData[dtx_message_header_struct.sizeof()+mheader.length:]
                print()
                print("there is remaining data: {} to process".format(len(remaining_data)))
                self.process_data(remaining_data)
        except ConstError:
            print("不认识的data")
        except Empty:
            print(len(unitData))
            print(len(self.previous_data))
            print(dtx_message_header_struct.sizeof())
            print(mheader.length)
            self.previous_data = unitData[dtx_message_header_struct.sizeof()+mheader.length:]
            print(len(self.previous_data))
            self.channelFragmenter = chanelFra
            print("Empty")
            return
        except StreamError:
            print("data 不完整 StreamError")
            self.previous_data = unitData
            return

    def printData(self,mheader,fdata,pheader,aux,data):
        if data is None and aux is None:
            print("empty DTXMessage")
            return
        if data == "_XCT_logDebugMessage:":
            print("get _XCT_logDebugMessage:") #data is a list
            for it in aux:
                print(it.value)
            return
        print("mheader: ", mheader)
        print("fdata: ", len(fdata))
        print("pheader: ", pheader)

        print("aux: ")
        # pp.pprint(aux)
        if aux is None:
            print("aux is null")
        else:
            for it in aux:
                print(it.value)
        
        print("data:",data)
        
    

    def process_out_data(self, unitData):
        try:
            if len(unitData) < 32:
                print("data 不完整")
                self.out_previous_data = unitData
                return
            # read dtx_message_header_struct.sizeof() data from the unitData
            headerData = unitData[:dtx_message_header_struct.sizeof()]
            mheader = dtx_message_header_struct.parse(headerData)
            # print("mheader: ", mheader)
            if mheader.fragmentCount > 1 and mheader.fragmentId == 0:
                # when reading multiple message fragments, the first fragment contains only a message header
                print("mheader.fragmentCount > 1 and mheader.fragmentId == 0")
                return
            # read mheader.length bytes behind the header from the unitData
            fdata = unitData[dtx_message_header_struct.sizeof():dtx_message_header_struct.sizeof()+mheader.length]
            # print("fdata: ", len(fdata))
            if len(fdata) != mheader.length:
                print("data 不完整")
                self.out_previous_data = unitData
                return

            chanelFra = self.out_channelFragmenter if self.out_channelFragmenter else ChannelFragmenter()
            chanelFra.add_fragment(mheader, fdata)
            stream = io.BytesIO(chanelFra.get())
            pheader = dtx_message_payload_header_struct.parse_stream(stream)
            # print("pheader: ", pheader)
            compression = (pheader.flags & 0xFF000) >> 12
            if compression:
                print("NotImplementedError('Compressed')")
                # raise NotImplementedError('Compressed')

            if pheader.auxiliaryLength:
                aux_struct= message_aux_t_struct.parse_stream(stream)
                aux = aux_struct.aux
            else:
                aux = None
            # print("aux: ")
            # pp.pprint(aux)
            obj_size = pheader.totalLength - pheader.auxiliaryLength
            data = stream.read(obj_size) if obj_size else None
            
            if data is not None:
                if len(data) != obj_size:
                    print("data 不完整")
                    self.out_previous_data = unitData
                    return
                try:
                    data = archiver.unarchive(data)
                except archiver.MissingClassMapping as e:
                    print("archiver.MissingClassMapping")
                    result = plistlib.loads(data)
                    print("result: ", result)
                    print(e)
                    # raise e
                except plistlib.InvalidFileException:
                    print(f'got an invalid plist: {data[:40]}')
            # print("data:", data)
            self.printData(mheader,fdata,pheader,aux,data)

            self.out_previous_data = b''
            # check if there is any remaining data in unitData
            if len(unitData) > dtx_message_header_struct.sizeof()+mheader.length:
                remaining_data = unitData[dtx_message_header_struct.sizeof()+mheader.length:]
                print()
                print("there is remaining data: {} to process".format(len(remaining_data)))
                self.process_out_data(remaining_data)
        except ConstError:
            print("不认识的data")
        except Empty:
            print(len(unitData))
            print(len(self.out_previous_data))
            print(dtx_message_header_struct.sizeof())
            print(mheader.length)
            self.out_previous_data = unitData[dtx_message_header_struct.sizeof()+mheader.length:]
            print(len(self.out_previous_data))
            self.out_channelFragmenter = chanelFra
            print("Empty")
            return
        except StreamError:
            print("data 不完整")
            self.out_previous_data = unitData
            return


    def parse_single_data(self, path):
        try:
            self.inbounding = ("inbound" in path)
            old_data = self.previous_data if self.inbounding else self.out_previous_data
            with open(path, 'rb') as f:
                fileData = f.read()
                unitData = old_data + fileData
                print(path, len(fileData))
                print("previous_data: ", len(old_data))
                print("unitData: ", len(unitData))
                if self.inbounding:
                    self.process_data(unitData)
                else:
                    self.process_out_data(unitData)
        except Exception as e:
            # pass
            print(e)
            print(path, '  failed')


def lookfor_header(path):
    with open(path, 'rb') as f:
        headerSize = dtx_message_header_struct.sizeof()
        fileData = f.read()
        fileLength = len(fileData)
        startIndex = 0
        while startIndex <= fileLength - headerSize + 1:
            print(startIndex)
            try:
                headerData = fileData[startIndex:startIndex+headerSize]
                mheader = dtx_message_header_struct.parse(headerData)
                print(mheader)
                break
            except Exception as e:
                pass
            startIndex += 1

def parse_plist_bin(path):
    with open(path, 'rb') as f:
        data = f.read()
        try:
            data = archiver.unarchive(data)
            print("data:", data)
        except archiver.MissingClassMapping as e:
            print("111111111111")
            result = plistlib.loads(data)
            print(result)
            raise e
        except plistlib.InvalidFileException:
            print(f'got an invalid plist: {data[:40]}')

def parseXCTestConfiguration():
    name = '/Users/isan/XCTestConfiguration.bin'
    with open(name, 'rb') as file:
        data = file.read()
        data = archiver.unarchive(data)

if __name__ == '__main__':
    helper = ParseDTXHelper()
    index = 1
    while index <= 263:
        directions = ['inbound', 'outbound']
        for direction in directions:
            path = '/Users/isan/runtest/xcode_1117_部分安装_62/dt.testmanagerd.remote_50705/{}_{}.bin'.format(str(index).zfill(4), direction)
            if os.path.isfile(path):
                print()
                print()
                helper.parse_single_data(path)
                break
        index += 1

# 还有问题的message
# 1.
# index = 226
# while index <= 227:
#     direction = 'inbound'
#     # direction = 'outbound'
#     path = '/Users/isan/runtest/packets_1023/dt.testmanagerd.remote_51725/{}_{}.bin'.format(str(index).zfill(4), direction)