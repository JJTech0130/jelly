import hashlib, macholibre
from jelly import Jelly
import unicorn

BINARY_HASH = "e1181ccad82e6629d52c6a006645ad87ee59bd13"
BINARY_PATH = "/Users/jjtech/Downloads/IMDAppleServices"

FAKE_DATA = {
    "iokit": {
        "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB": b"CK1340351BH8U",
		"4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM": b'\xb4\x8b\x19\x88\xb8\x80',
		"Fyp98tpgj": b'/ONK\xdd\xf3\x01f\x85[BK\x03W;\xdei',
		"Gq3489ugfi": b'\xd4J\xd2s\xcaJ\xd8\xd1<\xfcy\x96\x80\x19\xf9d\xe8',
		"IOMACAddress": b'\xee\xe9\xd3\x14\x05\xcf',
		"IOPlatformSerialNumber": "CK1350NCEUH",
		"IOPlatformUUID": "ABB178CD-25C5-5AFB-A749-B432FD683AE1",
		"abKPld1EcMni": b'\xbeT\x9c\xe8F\xf4\x02{d\xc7\xa1\xeb-\x1aA\xc3~',
		"board-id": b'Mac-F221BEC8\x00',
		"kbjfrfpoJU": b'l\x99\xea\xa6\x07\xefE\xb3\t\xab\x01\x05\xa2\xd6\x199\x80',
		"oycqAZloTNDm": b'\x95LQ@\x807\xaa?F\x11z\xf3s\x0e\x04_\x8f',
		"product-name": b'MacPro5,1\x00',
    },
	"root_disk_uuid": "FDB13F90-6FDA-3A57-BA48-CFF31478CAF2"
}

def load_binary() -> bytes:
    # Open the file at BINARY_PATH, check the hash, and return the binary
    # If the hash doesn't match, raise an exception
    b = open(BINARY_PATH, "rb").read()
    if hashlib.sha1(b).hexdigest() != BINARY_HASH:
        raise Exception("Hashes don't match")
    return b


def get_x64_slice(binary: bytes) -> bytes:
    # Get the x64 slice of the binary
    # If there is no x64 slice, raise an exception
    p = macholibre.Parser(binary)
    # Parse the binary to find the x64 slice
    off, size = p.u_get_offset(cpu_type="X86_64")
    return binary[off : off + size]


def nac_init(j: Jelly, cert: bytes):
    # Allocate memory for the cert
    cert_addr = j.malloc(len(cert))
    j.uc.mem_write(cert_addr, cert)

    # Allocate memory for the outputs
    out_validation_ctx_addr = j.malloc(8)
    out_request_bytes_addr = j.malloc(8)
    out_request_len_addr = j.malloc(8)

    # Call the function
    ret = j.instr.call(
        0xB1DB0,
        [
            cert_addr,
            len(cert),
            out_validation_ctx_addr,
            out_request_bytes_addr,
            out_request_len_addr,
        ],
    )

    #print(hex(ret))

    if ret != 0:
        n = ret & 0xffffffff
        n = (n ^ 0x80000000) - 0x80000000
        raise Exception(f"Error calling nac_init: {n}")
    
    # Get the outputs
    validation_ctx_addr = j.uc.mem_read(out_validation_ctx_addr, 8)
    request_bytes_addr = j.uc.mem_read(out_request_bytes_addr, 8)
    request_len = j.uc.mem_read(out_request_len_addr, 8)

    request_bytes_addr = int.from_bytes(request_bytes_addr, 'little')
    request_len = int.from_bytes(request_len, 'little')

    print(f"Request @ {hex(request_bytes_addr)} : {hex(request_len)}")

    request = j.uc.mem_read(request_bytes_addr, request_len)

    return validation_ctx_addr, request


INSTRS = []
def hook_code(uc, address: int, size: int, user_data):
    # if address > 0x800000 and address < 0x900000:
    #     raise Exception("DEAD")
    # if address == 0x39e24:
    #     # Print ret value
    #     ret = uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX)
    #     print(f"ret = {hex(ret)}")
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    # Rotate through the last 20 instructions
    #INSTRS.append(address)
    #if len(INSTRS) > 20:
    #    INSTRS.pop(0)



def malloc(j: Jelly, len: int) -> int:
    # Hook malloc
    # Return the address of the allocated memory
    print("malloc hook called with len = %d" % len)
    return j.malloc(len)


def memset_chk(j: Jelly, dest: int, c: int, len: int, destlen: int):
    print(
        "memset_chk called with dest = 0x%x, c = 0x%x, len = 0x%x, destlen = 0x%x"
        % (dest, c, len, destlen)
    )
    j.uc.mem_write(dest, bytes([c]) * len)
    return 0


def sysctlbyname(j: Jelly):
    return 0  # The output is not checked


def memcpy(j: Jelly, dest: int, src: int, len: int):
    print(f"called with trace: {INSTRS}")
    print("memcpy called with dest = 0x%x, src = 0x%x, len = 0x%x" % (dest, src, len))
    orig = j.uc.mem_read(src, len)
    j.uc.mem_write(dest, bytes(orig))
    return 0

CF_OBJECTS = []

# struct __builtin_CFString {
#     int *isa; // point to __CFConstantStringClassReference
#     int flags;
#     const char *str;
#     long length;
# }
import struct

def _parse_cfstr_ptr(j: Jelly, ptr: int) -> str:
    size = struct.calcsize("<QQQQ")
    data = j.uc.mem_read(ptr, size)
    isa, flags, str_ptr, length = struct.unpack("<QQQQ", data)
    str_data = j.uc.mem_read(str_ptr, length)
    return str_data.decode("utf-8")

def _parse_cstr_ptr(j: Jelly, ptr: int) -> str:
    data = j.uc.mem_read(ptr, 256) # Lazy way to do it
    return data.split(b"\x00")[0].decode("utf-8")

def IORegistryEntryCreateCFProperty(j: Jelly, entry: int, key: int, allocator: int, options: int):
    key_str = _parse_cfstr_ptr(j, key)
    if key_str in FAKE_DATA["iokit"]:
        fake = FAKE_DATA["iokit"][key_str]
        print(f"IOKit Entry: {key_str} -> {fake}")
        # Return the index of the fake data in CF_OBJECTS
        CF_OBJECTS.append(fake)
        return len(CF_OBJECTS) # NOTE: We will have to subtract 1 from this later, can't return 0 here since that means NULL
    else:
        print(f"IOKit Entry: {key_str} -> None")
        return 0
        
def CFGetTypeID(j: Jelly, obj: int):
    obj = CF_OBJECTS[obj - 1]
    if isinstance(obj, bytes):
        return 1
    elif isinstance(obj, str):
        return 2
    else:
        raise Exception("Unknown CF object type")
                                                                                                                      
def CFDataGetLength(j: Jelly, obj: int):
    obj = CF_OBJECTS[obj - 1]
    if isinstance(obj, bytes):
        return len(obj)
    else:
        raise Exception("Unknown CF object type")
    
def CFDataGetBytes(j: Jelly, obj: int, range_start: int, range_end: int, buf: int):
    obj = CF_OBJECTS[obj - 1]
    if isinstance(obj, bytes):
        data = obj[range_start:range_end]
        j.uc.mem_write(buf, data)
        print(f"CFDataGetBytes: {hex(range_start)}-{hex(range_end)} -> {hex(buf)}")
        return len(data)
    else:
        raise Exception("Unknown CF object type")
    
def CFDictionaryCreateMutable(j: Jelly) -> int:
    CF_OBJECTS.append({})
    return len(CF_OBJECTS)

def maybe_object_maybe_string(j: Jelly, obj: int):
    # If it's already a str
    if isinstance(obj, str):
        return obj
    elif obj > len(CF_OBJECTS):
        return obj
        #raise Exception(f"WTF: {hex(obj)}")
        # This is probably a CFString
       # return _parse_cfstr_ptr(j, obj)
    else:
        return CF_OBJECTS[obj - 1]

def CFDictionaryGetValue(j: Jelly, d: int, key: int) -> int:
    print(f"CFDictionaryGetValue: {d} {hex(key)}")
    d = CF_OBJECTS[d - 1]
    if key == 0xc3c3c3c3c3c3c3c3:
        key = "DADiskDescriptionVolumeUUIDKey" # Weirdness, this is a hack
    key = maybe_object_maybe_string(j, key)
    if isinstance(d, dict):
        if key in d:
            val = d[key]
            print(f"CFDictionaryGetValue: {key} -> {val}")
            CF_OBJECTS.append(val)
            return len(CF_OBJECTS)
        else:
            raise Exception("Key not found")
            return 0
    else:
        raise Exception("Unknown CF object type")
    
def CFDictionarySetValue(j: Jelly, d: int, key: int, val: int):
    d = CF_OBJECTS[d - 1]
    key = maybe_object_maybe_string(j, key)
    val = maybe_object_maybe_string(j, val)
    if isinstance(d, dict):
        d[key] = val
    else:
        raise Exception("Unknown CF object type")

def DADiskCopyDescription(j: Jelly) -> int:
    description = CFDictionaryCreateMutable(j)
    CFDictionarySetValue(j, description, "DADiskDescriptionVolumeUUIDKey", FAKE_DATA["root_disk_uuid"])
    return description    

def CFStringCreate(j: Jelly, string: str) -> int:
    CF_OBJECTS.append(string)
    return len(CF_OBJECTS)

def CFStringGetLength(j: Jelly, string: int) -> int:
    string = CF_OBJECTS[string - 1]
    if isinstance(string, str):
        return len(string)
    else:
        raise Exception("Unknown CF object type")

def CFStringGetCString(j: Jelly, string: int, buf: int, buf_len: int, encoding: int) -> int:
    string = CF_OBJECTS[string - 1]
    if isinstance(string, str):
        data = string.encode("utf-8")
        j.uc.mem_write(buf, data)
        print(f"CFStringGetCString: {string} -> {hex(buf)}")
        return len(data)
    else:
        raise Exception("Unknown CF object type")
    
def IOServiceMatching(j: Jelly, name: int) -> int:
    # Read the raw c string pointed to by name
    name = _parse_cstr_ptr(j, name)
    print(f"IOServiceMatching: {name}")
    # Create a CFString from the name
    name = CFStringCreate(j, name)
    # Create a dictionary
    d = CFDictionaryCreateMutable(j)
    # Set the key "IOProviderClass" to the name
    CFDictionarySetValue(j, d, "IOProviderClass", name)
    # Return the dictionary
    return d
    
def IOServiceGetMatchingService(j: Jelly) -> int:
    return 92

ETH_ITERATOR_HACK = False
def IOServiceGetMatchingServices(j: Jelly, port, match, existing) -> int:
    global ETH_ITERATOR_HACK
    ETH_ITERATOR_HACK = True
    # Write 93 to existing
    j.uc.mem_write(existing, bytes([93]))
    return 0

def IOIteratorNext(j: Jelly, iterator: int) -> int:
    global ETH_ITERATOR_HACK
    if ETH_ITERATOR_HACK:
        ETH_ITERATOR_HACK = False
        return 94
    else:
        return 0
    
def bzero(j: Jelly, ptr: int, len: int):
    j.uc.mem_write(ptr, bytes([0]) * len)
    return 0

def IORegistryEntryGetParentEntry(j: Jelly, entry: int, _, parent: int) -> int:
    j.uc.mem_write(parent, bytes([entry + 100]))
    return 0

import requests, plistlib
def get_cert():
    resp = requests.get("http://static.ess.apple.com/identity/validation/cert-1.0.plist")
    resp = plistlib.loads(resp.content)
    return resp["cert"]

def arc4random(j: Jelly) -> int:
    import random
    return random.randint(0, 0xFFFFFFFF)

def main():
    binary = load_binary()
    binary = get_x64_slice(binary)
    # Create a Jelly object from the binary
    j = Jelly(binary)
    hooks = {
        "_malloc": malloc,
        "___stack_chk_guard": lambda: 0,
        "___memset_chk": memset_chk,
        "_sysctlbyname": lambda _: 0,
        "_memcpy": memcpy,
        "_kIOMasterPortDefault": lambda: 0,
        "_IORegistryEntryFromPath": lambda _: 1,
        "_kCFAllocatorDefault": lambda: 0,
        "_IORegistryEntryCreateCFProperty": IORegistryEntryCreateCFProperty,
        "_CFGetTypeID": CFGetTypeID,
        "_CFStringGetTypeID": lambda _: 2,
        "_CFDataGetTypeID": lambda _: 1,
        "_CFDataGetLength": CFDataGetLength,
        "_CFDataGetBytes": CFDataGetBytes,
        "_CFRelease": lambda _: 0,
        "_IOObjectRelease": lambda _: 0,
        "_statfs$INODE64": lambda _: 0,
        "_DASessionCreate": lambda _: 201,
        "_DADiskCreateFromBSDName": lambda _: 202,
        "_kDADiskDescriptionVolumeUUIDKey": lambda: 0,
        "_DADiskCopyDescription": DADiskCopyDescription,
        "_CFDictionaryGetValue": CFDictionaryGetValue,
        "_CFUUIDCreateString": lambda _, __, uuid: uuid,
        "_CFStringGetLength": CFStringGetLength,
        "_CFStringGetMaximumSizeForEncoding": lambda _, length, __: length,
        "_CFStringGetCString": CFStringGetCString,
        "_free": lambda _: 0,
        "_IOServiceMatching": IOServiceMatching,
        "_IOServiceGetMatchingService": IOServiceGetMatchingService,
        "_CFDictionaryCreateMutable": CFDictionaryCreateMutable,
        "_kCFBooleanTrue": lambda: 0,
        "_CFDictionarySetValue": CFDictionarySetValue,
        "_IOServiceGetMatchingServices": IOServiceGetMatchingServices,
        "_IOIteratorNext": IOIteratorNext,
        "___bzero": bzero,
        "_IORegistryEntryGetParentEntry": IORegistryEntryGetParentEntry,
        "_arc4random": arc4random



    }
    j.setup(hooks)
    #j.uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)

    #cert = get_cert()
    cert = b'\x01\x02\x00\x00\x04\x160\x82\x04\x120\x82\x02\xfa\xa0\x03\x02\x01\x02\x02\x01\x1c0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x000b1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\n\x13\nApple Inc.1&0$\x06\x03U\x04\x0b\x13\x1dApple Certification Authority1\x160\x14\x06\x03U\x04\x03\x13\rApple Root CA0\x1e\x17\r110126190134Z\x17\r190126190134Z0\x81\x851\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\n\x0c\nApple Inc.1&0$\x06\x03U\x04\x0b\x0c\x1dApple Certification Authority1907\x06\x03U\x04\x03\x0c0Apple System Integration Certification Authority0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xda\xe0\x0f\x98\x97\xcbX)\x86*\x0b\xb8\x9e\x19Z1\xc3-\x0ej,R\x01\xee\x1d\x03\xfb\x82Ai\xcdP&6z\xb7\x0co\x0e9\x03\xb8\xd4\x18V\xa3\x08\xb2<\xc3\xfb6A\xe4\xd7\xc8g`2\x0bN2}\x87\xf7\xfd\xcdS\xb0\x1a\xba\xfc\x1fl\xc9E\x07\xad\x828\xf3\xa8|\xc4N\xc2\xb1V\xd9>\xb2mm\x04A\x1a\xc1\x9aG\xc0\xac\x15|-x\x91\xab\x07\xa2e\xb1z\x83\xdd\x98Kw@\xd8\xeeP\xeb\xc7kX\x08\x06\x97WU}\'\xf8\n\xe6\xb5\x15\xe7\xa7\x93\xf9\xf1\x80\xe6By?\x16\xd32\x9d\x11vA)\n1\t\xef\x0f[\xf8\xf3\xa7\xa9\xf7R\r\xbb\xf8-t\xac\xa6I\x1f\x1f\xce{\x05\xa7\x85=\xbe\xcf\xa2\xa7\xaa#\x85f\xfe\xc5\x16\x12~[\xe21w\x91\x02\t\xdf~~\xe4\x8a\xe0\xecA\xac\x17,\x04\xe0\xbcy\xa4\x89xD\x06\x8b;K\xa0\xbc\x84\xe2\xb0\x82\xb52\xbe\x04\x1c\x03\xed\x82>u7\x14\xcfu\x9f\x821m\xcf\t\x14\x86\xd1\'\x02\x03\x01\x00\x01\xa3\x81\xae0\x81\xab0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x860\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xf00sc\xf2\xef\x1d\xac\xcc\xe6\t2\xc1\xfayz\xb1iPh0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14+\xd0iG\x94v\t\xfe\xf4k\x8d.@\xa6\xf7GM\x7f\x08^06\x06\x03U\x1d\x1f\x04/0-0+\xa0)\xa0\'\x86%http://www.apple.com/appleca/root.crl0\x10\x06\n*\x86H\x86\xf7cd\x06\x02\x04\x04\x02\x05\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00={\x8f\xad\x1f\x0c"\x8a\x9bK\xa3\xcf\xf8+\xb0\x1fh\xe1\x0c\xf7\x9c$\x83\x16\x03-\xd3\xb2\xa8\xd0C\xe8\xaf<\x97&\xc8\xad\xd5,\xc4LUS\x01I\xd0\xe2\xb4\xfb\xe6\xdbr\xd1\x98\xbb\xfc\x9b\xc8N\xb7\x8f\xcce\x86\x7fD\xb9\xda\'*N\xdf\xcb\xdf\xd3}\xdfAq\xf8\xb3\xc0\x1d\xa2\n3\xb9\xec+\xc5sr\xfb\xe1\xca]\x8e/4\xf4k\xc4O\x0f\xc8\x8a\xac\x0f\xfbo%n\xb7\xae\x8e\xc7\xe4\x02\xb8 N]VLI\x97\xb1$t~\xc9\x93\x934\x8c\x99\xd1\xa7\xc0\x1c\xd3\xd4\xc2\xaei\xeb\x9f\x9fW\xe2h\xc7\xca\xd5\xc5"\x82dAX\xfex\xd1\xca\xc1\xf96jkD\xf7\xb3\x86rzd@\x171\x9d\xbc\xacu\xf0\xfa3Q\xe5\xbd\x01jX?\xf0\x00\xae\x99\\\n\xc2\xc9\xe9^\x1c\x87\x02\xec\xa0\x08UA*\x9b\x8cd\x85\x8eP\x03\xcd\xe0\x11\xaf\xcer\x19\xebR\xf3\xaf\x92\xad\x93.\x94\x9d\xd6\xaf\xff\xc0&\xf1\xde\x94\x92\x1c\xd9\xbc=6\xccU\xfa8\xdb\x00\x00\x0510\x82\x05-0\x82\x04\x15\xa0\x03\x02\x01\x02\x02\x08K,\x91H\x1d\x9b}\xa00\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x000\x81\x851\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\n\x0c\nApple Inc.1&0$\x06\x03U\x04\x0b\x0c\x1dApple Certification Authority1907\x06\x03U\x04\x03\x0c0Apple System Integration Certification Authority0\x1e\x17\r110325011332Z\x17\r140324011332Z0i1\x1d0\x1b\x06\x03U\x04\x03\x0c\x14DRM Technologies A011&0$\x06\x03U\x04\x0b\x0c\x1dApple Certification Authority1\x130\x11\x06\x03U\x04\n\x0c\nApple Inc.1\x0b0\t\x06\x03U\x04\x06\x13\x02US0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xb4\x06m~es\x97\xe1\xbfI\xb1\xfa\x9a".\xa7\xd3q\x81 kIA\x15\xc2\xdb`z\xc6\xa2\xb7Mz/\x8e\xc1c\x07\x1c\x04\xcc\x93\xd8\xe0\r\xc8\xb8\xf2[\xcem\xfaB\xcb\x10@\xc2$\n\xa7\xe4\x1d&\x82\x8a>0\x86]\xed\x178\xee\x87\xab\xbd\xe8HJIw\x85.\xb7\x91\x84\x9b)}A\x05\xa0y\xf5\xad\x8c\xc1\x0b\xd8\x9di\xe7\x9c\xb2\xa9F\xd0K\xfe\t\x18P$\x8aYG+"UG\xedQ"\x9dB\xe9\x9d\xee\x81\xc3G\xcd\xe4o\n*?O+\xd2\x04\xd0\xb8\x8c\xe8d\x98\xdf\xce`S\x9b\x88\x1a\xcf\xd4\xc2\rte\xbf\xf3\x85\x87_K\x87\x10\xa2\x87\x8am>@U\x0e\xf9\x9f\x99\xcc2\x93\x83Q\x88\xc9\xb9\xf8^\xc9\x19_\x17\xe7k\x9b|:\xdd\xffh\xdf\xd4\xd14Ut\xec\xf7K\xe8\x1c\x90u\x85\xf2\xfcC\xff\xa5D#R?\xfb\xf5!\xe3\x83\x16?\xbe\nt\xf9<t\x99j\xfe?\xd2Z\xa1P\xe3.\x8bH\r"&;\xd5\x9eI\x02\x03\x01\x00\x01\xa3\x82\x01\xba0\x82\x01\xb60\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xd2$#\xfb\xeb\xe8\x8e\x8fq\x9c\x84\xeebs=\xe9^$\t/0\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\xf00sc\xf2\xef\x1d\xac\xcc\xe6\t2\xc1\xfayz\xb1iPh0\x82\x01\x0e\x06\x03U\x1d \x04\x82\x01\x050\x82\x01\x010\x81\xfe\x06\t*\x86H\x86\xf7cd\x05\x010\x81\xf00(\x06\x08+\x06\x01\x05\x05\x07\x02\x01\x16\x1chttp://www.apple.com/appleca0\x81\xc3\x06\x08+\x06\x01\x05\x05\x07\x02\x020\x81\xb6\x0c\x81\xb3Reliance on this certificate by any party assumes acceptance of the then applicable standard terms and conditions of use, certificate policy and certification practice statements.0/\x06\x03U\x1d\x1f\x04(0&0$\xa0"\xa0 \x86\x1ehttp://crl.apple.com/asica.crl0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa00\x13\x06\n*\x86H\x86\xf7cd\x06\x0c\x01\x01\x01\xff\x04\x02\x05\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00}y\xa7cnA;\xbe\xc1\xce\xb1\x8c\xfam0 \xb8\xbaI0\x92=\x1dU\xce\xb9\xc2-Kb\xc5\xca@\xf6\xb7\xbc\xb1\xf6\xd2\xa6\xfa\xad\x01kO\x1c\xcc\xae\xceF \xff\xc2\xb3\xc0,wO\xd0\x13DL\x87\xc7a-\x0f\xc7\xccC.7:7\xfd\xae\x98\x9a\x12\xb6I\xb0\xaaw\xd3S\x81\x96\x80\xcd\x84\xdbs\xaaG\xa8 V6\xc2\xd9\xa5\xe9\x0c<"\x1dy\xef\xe7\xb0O\t}^\xfb\xb2"\xa3\xb6\xf7#%\t\x83y\xa84V\x84\xe6E\xad"\xa1\x1cU\x9c\xa2/\x1f\xb6!\xb9\xff\xd8\x0f\xc9s\tv\xf0\x03\x17\x19\x8f\xe9\xa3\xfc\xe6B\xcb_d\x86\x96\x8ch?\xc2\xa0XB\xd4\x9fvm\x95\xbf\xc0\xf7\xdb\x14t\xfcZ\xa8\x82\xc7\xa6\xfcV\x8a7\xb7\xc8r\x9c\xbc\x9bD\xd1F\xe2\x8d$\xd9\x7f\'y\xf1t\xb9\xc5\xb2\xb0\xc2\xe1&\x06\xe4\xff\xaf\xa5\x0b\xd9\xa3\x1e\x95\xdbD\x91\xcc\xe9K\x022\x03\xe6R\xf6\xa7*Z#4\xd0\x1d\x17\xf2\xeb\xea\xc2y\n\xe9'
    print(cert)
    print(nac_init(j,cert))
    # try:
    # except Exception as e:
    #     print(e)
    #     print(INSTRS)
    #     j.debug_registers()


if __name__ == "__main__":
    main()
