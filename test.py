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
    j.instr.call(
        0xB1DB0,
        [
            cert_addr,
            len(cert),
            out_validation_ctx_addr,
            out_request_bytes_addr,
            out_request_len_addr,
        ],
    )

    # Get the outputs
    validation_ctx_addr = j.uc.mem_read(out_validation_ctx_addr, 8)
    request_bytes_addr = j.uc.mem_read(out_request_bytes_addr, 8)
    request_len = j.uc.mem_read(out_request_len_addr, 8)

    request = j.uc.mem_read(request_bytes_addr, request_len)

    return validation_ctx_addr, request


def hook_code(uc, address: int, size: int, user_data):
    if address > 0x800000 and address < 0x900000:
        raise Exception("DEAD")
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))


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
    print("memcpy called with dest = 0x%x, src = 0x%x, len = 0x%x" % (dest, src, len))
    orig = j.uc.mem_read(dest, len)
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
    }
    j.setup(hooks)
    j.uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)
    nac_init(j, b"Hello, world!")


if __name__ == "__main__":
    main()
