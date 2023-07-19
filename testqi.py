# Loads IMDAppleServices.framework binary and calls hardcoded functions using Unicorn Engine
BINARY_HASH = "e1181ccad82e6629d52c6a006645ad87ee59bd13"
BINARY_PATH = "/Users/jjtech/Downloads/IMDAppleServices"

from unicorn import *
from unicorn.x86_const import *

import macholibre

import hashlib


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
    return binary[off:off+size]

def start_unicorn() -> Uc:
    # Start the unicorn engine
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    return mu

def map_macho_binary(mu: Uc, binary: bytes):
    # Expects a x64 slice of the binary
    map_len = (len(binary) + mu.ctl_get_page_size() - 1) & ~(mu.ctl_get_page_size() - 1)
    print(f"Mapping binary of size {hex(len(binary))} ({hex(map_len)}) at 0x0")

    mu.mem_map(0x0, map_len)
    mu.mem_write(0x0, binary)

    # Unmap the first page so we can catch NULL derefs
    mu.mem_unmap(0x0, mu.ctl_get_page_size())

STACK_BASE = 0x00300000
STACK_SIZE = 0x00100000
def create_stack(mu: Uc):
    stack_base = STACK_BASE
    stack_size = STACK_SIZE
    
    mu.mem_map(stack_base, stack_size)
    mu.mem_write(stack_base, b"\x00" * stack_size)
    
    mu.reg_write(UC_X86_REG_ESP, stack_base + 0x800)
    mu.reg_write(UC_X86_REG_EBP, stack_base + 0x1000)

def push_stack(mu: Uc, data: bytes):
    esp = mu.reg_read(UC_X86_REG_ESP)
    mu.mem_write(esp - len(data), data)
    mu.reg_write(UC_X86_REG_ESP, esp - len(data))

def main():
    binary = load_binary()
    binary = get_x64_slice(binary)
    mu = start_unicorn()
    map_macho_binary(mu, binary)

    create_stack(mu)

    # Create a return address
    STOP_ADDRESS = 0x00900000
    mu.mem_map(STOP_ADDRESS, 0x1000)
    mu.mem_write(STOP_ADDRESS, b"\x90" * 0x1000)

    push_stack(mu, STOP_ADDRESS.to_bytes(8, "little"))

    print("Starting emulation")
    mu.emu_start(0xb1db0, STOP_ADDRESS)
    print("Emulation done")
    print("Return value:", hex(mu.reg_read(UC_X86_REG_RAX)))


    # Set the return address to 0x1000
    #mu.mem_write(0x30000 + 0x8, b"\x00\x10\x00\x00\x00\x00\x00\x00")

    # Call the function
    #mu.emu_start(0xb1db0, 0xb1db0 + 0x5)
    

    

if __name__ == "__main__":
    main()


    

# binary = load_binary()

# import macholibre

# #print(macholibre.Parser(binary).parse())
# p = macholibre.Parser(binary)
# off, size = p.u_get_offset(cpu_type="X86_64")
# import json
# #print(json.dumps(p.parse_macho(off, size), indent=4))
# m = p.parse_macho(off, size)
# #syms = m['symtab']
# lcs = list(map(lambda x: x['cmd'], m['lcs']))
# symtab = m['lcs'][lcs.index('SYMTAB')]
# stroff = symtab['stroff'] + off
# psymtab = m['symtab']

# old = p.file.tell()
# for sym in psymtab:
#     p.file.seek(stroff + sym['n_strx'])
#     #print(p.get_string())
#     sym['name'] = p.get_string()
#     print(sym)
# p.file.seek(old)


#print(syms['stroff'])


# BASIC OUTLINE

# 1. Get sub for our arch
# 2. Copy to memory (just do all prots RWX)
# 3. Look at symtab and stub ALL of it, can we just detect when we hit an address? Or do we actually have to assemble a tramp.... no LUT, can just call by name? exec + fstr at worst
# 4. Try calling by setting up registers and basic stack, then jumping? See if any tramps are called, check if returns!
# 5. PROFIT?

#mu = Uc(UC_ARCH_X86, UC_MODE_32)
#mu.hook_add # Figure this out to hook addr?


# def parse_fat(binary: bytes) -> list(tuple[bytes, int]):
#     """
#     Parses a fat binary and returns a list of tuples containing the binary data and the cpu type
#     """
#     # Make sure it has the magic bytes
#     if binary[0:4] != b"\xca\xfe\xba\xbe":
#         print("Not a fat binary")
#         return [(binary, 0)]  # CPU type 0 is the default for non-fat binaries
    
#     binary = binary[4:]  # Remove the magic bytes

#     # Get the number of architectures
#     num_archs = int.from_bytes(binary[4:8], "big")
#     print(f"Number of architectures: {num_archs}")

#     # Get the architectures
#     archs = []

#     LENGTH_OF_INT = 4
#     LENGTH_OF_ARCH = 5 * LENGTH_OF_INT

#     def int_for_arch(int_num: int, arch_num: int) -> int:
#         return int.from_bytes(
#             binary[
#                 (arch_num * LENGTH_OF_ARCH)
#                 + (int_num * LENGTH_OF_INT) : (arch_num * LENGTH_OF_ARCH)
#                 + ((int_num + 1) * LENGTH_OF_INT)
#             ],
#             "big",
#         )

#     for i in range(num_archs):
#         cpu_type = int_for_arch(0, i)
#         cpu_subtype = int_for_arch(1, i)
#         offset = int_for_arch(2, i)
#         size = int_for_arch(3, i)
#         align = int_for_arch(4, i)
#         print(f"CPU type: {hex(cpu_type)}")
#         print(f"CPU subtype: {cpu_subtype}")
#         print(f"Offset: {offset}")
#         print(f"Size: {size}")
#         print(f"Align: {align}")
#         archs.append((binary[offset : offset + size], cpu_type))
#         # end = start + LENGTH_OF_ARCH
#         # archs.append(binary[start:end])
#     return archs


# parsed = parse_fat(binary)
# print(len(parsed[0][0]), parsed[0][1])
# print(len(parsed[1][0]), parsed[1][1])


# # print(binary[0:4].hex())

# # code to be emulated
# X86_CODE32 = b"\x41\x4a"  # INC ecx; DEC edx

# # memory address where emulation starts
# ADDRESS = 0x1000000

# print("Emulate i386 code")
# try:
#     # Initialize emulator in X86-32bit mod
#     # map 2MB memory for this emulation
#     mu.mem_map(ADDRESS, 2 * 1024 * 1024)

#     # write machine code to be emulated to memory
#     mu.mem_write(ADDRESS, X86_CODE32)

#     # initialize machine registers
#     mu.reg_write(UC_X86_REG_ECX, 0x1234)
#     mu.reg_write(UC_X86_REG_EDX, 0x7890)

#     # emulate code in infinite time & unlimited instructions
#     mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

#     # now print out some registers
#     print("Emulation done. Below is the CPU context")

#     r_ecx = mu.reg_read(UC_X86_REG_ECX)
#     r_edx = mu.reg_read(UC_X86_REG_EDX)
#     print(">>> ECX = 0x%x" % r_ecx)
#     print(">>> EDX = 0x%x" % r_edx)

# except UcError as e:
#     print("ERROR: %s" % e)
