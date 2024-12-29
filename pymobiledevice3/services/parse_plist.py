import plistlib
from bpylist2 import archiver
from bpylist2.archiver import ArchivedObject
import uuid
import json

def type_serializer(o):
    # This will handle any unknown or non-native types.
    return f"<{o.__class__.__name__}>"

class XCTestConfiguration():
    @staticmethod
    def decode_archive(archive_obj):
        metadata_dict = {}
        for key, value in archive_obj.object.items():
            try:
                print(key)
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
                print(key)
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
                print(key)
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
                print(key)
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
                print(key)
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
                           'XCTestConfiguration': XCTestConfiguration,
                           'XCTRepetitionPolicy': XCTRepetitionPolicy,
                           'XCTRuntimeIssueDetectionPolicy': XCTRuntimeIssueDetectionPolicy,
                           })

def parse_plist_bin(path):
    with open(path, 'rb') as f:
        data = f.read()
        try:
            data = archiver.unarchive(data)
            print(json.dumps(data, default=type_serializer))
        except archiver.MissingClassMapping as e:
            result = plistlib.loads(data)
            print(result)
            raise e
        except plistlib.InvalidFileException:
            print(f'got an invalid plist: {data[:40]}')
import os
if __name__ == '__main__':
    # path = "./data/capability.bin"
    path = "./data/XCTAttachmentFutureMetadata.bin"
    # path = "./data/XCTestConfiguration.bin"
    parse_plist_bin(path)