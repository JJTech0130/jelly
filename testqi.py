# Loads IMDAppleServices.framework binary and calls hardcoded functions using Unicorn Engine
BINARY_HASH = "e1181ccad82e6629d52c6a006645ad87ee59bd13"
BINARY_PATH = "/Users/jjtech/Downloads/IMDAppleServices"

from unicorn import *
from unicorn.x86_const import *

import macholibre
#import leb128

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

    # Parse the binary so we can process binds
    p = macholibre.Parser(binary)
    m = p.parse()
    #print(p.symtab)
    #print(binary[p.dysymtab['indirectsymoff']:])
    #print(p.strtab)
    #print(p.segments[0])
    #print(len(p.segments))
    #print(p.segments[2])
    for seg in p.segments:
         #print(seg['name'])
        for section in seg['sects']:
            #print(f"{section['name']} : {section['type']}")
            if section['type'] == 'LAZY_SYMBOL_POINTERS' or section['type'] == 'NON_LAZY_SYMBOL_POINTERS':
                #print(section)
                #pass
                parse_lazy_binds(mu, section['r1'], section, binary[p.dysymtab['indirectsymoff']:], binary[p.symtab['stroff']:], binary[p.symtab['symoff']:])

    # TODO: Deal with in-segment binds

    #print(p.dyld_info)
    parse_binds(mu, binary[p.dyld_info['bind_off']:p.dyld_info['bind_off']+p.dyld_info['bind_size']], p.segments)

BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0
BIND_OPCODE_THREADED = 0xD0

BIND_TYPE_POINTER = 1

DEAD_BIND = 0x800000

BINDS = {
    'deadbeef': 0xDEADBEEF,
    '___stack_chk_guard': DEAD_BIND,
    'n': DEAD_BIND,
    'radr://5614542': DEAD_BIND,
    '__FTFakeSMSDeviceID': DEAD_BIND,
    #'_malloc': 0xDEADEEBB
}

logged_unknown_binds = set()

def do_bind(mu: Uc, type, location, name):
    global logged_unknown_binds
    if type == 1: # BIND_TYPE_POINTER
        if name in BINDS:
            mu.mem_write(location, BINDS[name].to_bytes(8, byteorder='little'))
        else:
            if name not in logged_unknown_binds:
                logged_unknown_binds.add(name)
                print(f"Unknown bind {name[1:]}")
            if name == "_malloc":
                print("MALLOC WAS HERE")
            #pass
            #print(f"Unknown bind {name}")
    else:
        print(f"Unknown bind type {type}")

from io import BytesIO

def c_string(bytes, start: int = 0) -> str:
    out = ''
    i = start
    
    while True:
        if i > len(bytes) or bytes[i] == 0:
            break
        out += chr(bytes[i])
        #print(start)
        #print(chr(bytes[i]))
        i += 1
    return out


# " indirect " not lazy
def parse_lazy_binds(mu: Uc, indirect_offset, section, dysimtab, strtab, symtab):
    print(f"Doing binds for {section['name']}")
    for i in range(0, int(section['size']/8)):     
        # Parse into proper list?   
        dysym = dysimtab[(indirect_offset + i)*4:(indirect_offset + i)*4+4]
        dysym = int.from_bytes(dysym, 'little')
        index = dysym & 0x3fffffff

        # Proper list too?
        symbol = symtab[index * 16:(index * 16) + 4]
        strx = int.from_bytes(symbol, 'little')

        name = c_string(strtab, strx) # Remove _ at beginning
        #print(f"Lazy bind for {hex(section['offset'] + (i * 8))} : {name}")
        do_bind(mu, 1, section['offset'] + (i * 8), name)


def decodeULEB128(bytes: BytesIO) -> int:
    result = 0
    shift = 0
    while True:
        b = bytes.read(1)[0]
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result

 
def parse_binds(mu: Uc, binds: bytes, segments):
    BIND_OPCODE_MASK = 0xF0
    BIND_IMMEDIATE_MASK = 0x0F
    blen = len(binds)
    binds: BytesIO = BytesIO(binds)
    #print(binds)

    #offset = 0

    ordinal = 0
    symbolName = ''
    type = BIND_TYPE_POINTER
    addend = 0
    segIndex = 0
    segOffset = 0

    while binds.tell() < blen:
        current = binds.read(1)[0]
        opcode = current & BIND_OPCODE_MASK
        immediate = current & BIND_IMMEDIATE_MASK

        #print(f"{hex(offset)}: {hex(opcode)} {hex(immediate)}")

        if opcode == BIND_OPCODE_DONE:
            print("BIND_OPCODE_DONE")
            break
        elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            ordinal = immediate   
        elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            #ordinal = uLEB128(&p);
            ordinal = decodeULEB128(binds)
            #raise NotImplementedError("BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB")
        elif opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            if (immediate == 0):
                ordinal = 0
            else:
                ordinal = BIND_OPCODE_MASK | immediate
        elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            # Parse string until null terminator
            symbolName = ''
            while True:
                b = binds.read(1)[0]
                if b == 0:
                    break
                symbolName += chr(b)
            #while binds[offset] != 0:
            #    symbolName += chr(binds[offset])
            #    offset += 1
            #offset += 1
            #print(f"Symbol name: {symbolName}")
        elif opcode == BIND_OPCODE_SET_TYPE_IMM:
            type = immediate
        elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
            #addend = sLEB128(&p);
            raise NotImplementedError("BIND_OPCODE_SET_ADDEND_SLEB")
        elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            segIndex = immediate
            segOffset = decodeULEB128(binds)
            #raise NotImplementedError("BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB")
        elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
            segOffset += decodeULEB128(binds)
            #segOffset += uLEB128(&p);
            #raise NotImplementedError("BIND_OPCODE_ADD_ADDR_ULEB")
        elif opcode == BIND_OPCODE_DO_BIND:
            do_bind(mu, type, segments[segIndex]['offset'] + segOffset, symbolName)
            segOffset += 8
        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            do_bind(mu, type, segments[segIndex]['offset'] + segOffset, symbolName)
            segOffset += decodeULEB128(binds) + 8
            #bind(type, (cast(void**) &segments[segIndex][segOffset]), symbolName, addend, generateFallback);
            #segOffset += uLEB128(&p) + size_t.sizeof;
            #raise NotImplementedError("BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB")
        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            #bind(type, (cast(void**) &segments[segIndex][segOffset]), symbolName, addend, generateFallback);
            do_bind(mu, type, segments[segIndex]['offset'] + segOffset, symbolName)
            segOffset += immediate * 8 + 8
        elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count = decodeULEB128(binds)
            skip = decodeULEB128(binds)
            for i in range(count):
                do_bind(mu, type, segments[segIndex]['offset'] + segOffset, symbolName)
                segOffset += skip + 8
            # uint64_t count = uLEB128(&p);
            # uint64_t skip = uLEB128(&p);
            # for (uint64_t i = 0; i < count; i++) {
            #     bind(type, (cast(void**) &segments[segIndex][segOffset]), symbolName, addend, generateFallback);
            #     segOffset += skip + size_t.sizeof;
            # }
            #raise NotImplementedError("BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB")
        else:
            print(f"Unknown bind opcode {opcode}")



STACK_BASE = 0x00300000
STACK_SIZE = 0x00100000
def create_stack(mu: Uc):
    stack_base = STACK_BASE
    stack_size = STACK_SIZE
    
    mu.mem_map(stack_base, stack_size)
    mu.mem_write(stack_base, b"\x00" * stack_size)
    
    mu.reg_write(UC_X86_REG_ESP, stack_base + stack_size)
    mu.reg_write(UC_X86_REG_EBP, stack_base + stack_size)

def push_stack(mu: Uc, data: bytes):
    esp = mu.reg_read(UC_X86_REG_ESP)
    mu.mem_write(esp - len(data), data)
    mu.reg_write(UC_X86_REG_ESP, esp - len(data))

HEAP_BASE = 0x00400000
HEAP_SIZE = 0x00100000

HEAP_USE  = 0x0

def create_heap(mu: Uc):
    mu.mem_map(HEAP_BASE, HEAP_SIZE)
    mu.mem_write(HEAP_BASE, b"\x00" * HEAP_SIZE)

def malloc(mu: Uc, size: int):
    global HEAP_USE
    HEAP_USE += size
    return HEAP_BASE + HEAP_USE - size


STOP_ADDRESS = 0x00900000


def call_function(mu: Uc, addr: int, args: list[int]):
    # Put the first 6 args in registers
    mu.reg_write(UC_X86_REG_RDI, args[0] if len(args) > 0 else 0)
    mu.reg_write(UC_X86_REG_RSI, args[1] if len(args) > 1 else 0)
    mu.reg_write(UC_X86_REG_RDX, args[2] if len(args) > 2 else 0)
    mu.reg_write(UC_X86_REG_RCX, args[3] if len(args) > 3 else 0)
    mu.reg_write(UC_X86_REG_R8, args[4] if len(args) > 4 else 0)
    mu.reg_write(UC_X86_REG_R9, args[5] if len(args) > 5 else 0)

    print("Arguments: ", [hex(x) for x in args])

    # Push the rest of the args on the stack
    for arg in args[6:]:
        push_stack(mu, arg.to_bytes(8, "little"))

    # Push return address
    push_stack(mu, STOP_ADDRESS.to_bytes(8, "little"))

    print(f"RBP: {hex(mu.reg_read(UC_X86_REG_RBP))}, RSP: {hex(mu.reg_read(UC_X86_REG_RSP))}")

    show_registers(mu)

    # Call the function
    mu.emu_start(addr, STOP_ADDRESS)

    # Get the return value
    return mu.reg_read(UC_X86_REG_RAX)

#NACInit(const void *cert_bytes, int cert_len, void **out_validation_ctx,
#            void **out_request_bytes, int *out_request_len)

def nac_init(mu: Uc, cert: bytes):
    # Allocate memory for the cert
    cert_addr = malloc(mu, len(cert))
    mu.mem_write(cert_addr, cert)

    # Allocate memory for the outputs
    out_validation_ctx_addr = malloc(mu, 8)
    out_request_bytes_addr = malloc(mu, 8)
    out_request_len_addr = malloc(mu, 8)

    # Call the function
    ret = call_function(mu, 0xb1db0, [cert_addr, len(cert), out_validation_ctx_addr, out_request_bytes_addr, out_request_len_addr])

    # Get the outputs
    validation_ctx_addr = mu.mem_read(out_validation_ctx_addr, 8)
    request_bytes_addr = mu.mem_read(out_request_bytes_addr, 8)
    request_len = mu.mem_read(out_request_len_addr, 8)

    request = mu.mem_read(request_bytes_addr, request_len)

    return validation_ctx_addr, request

def hook_mem_invalid(uc, access, address, size, value, user_data):
    """For Debugging Use Only"""
    eip = uc.reg_read(UC_X86_REG_EIP)
    show_registers(uc)
    if access == UC_MEM_WRITE:
        print("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, eip, size, value))
    if access == UC_MEM_READ:
        print("invalid READ of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_FETCH:
        print("UC_MEM_FETCH of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_READ_UNMAPPED:
        print("UC_MEM_READ_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_WRITE_UNMAPPED:
        print("UC_MEM_WRITE_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_FETCH_UNMAPPED:
        print("UC_MEM_FETCH_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_WRITE_PROT:
        print("UC_MEM_WRITE_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_FETCH_PROT:
        print("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_FETCH_PROT:
        print("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_READ_AFTER:
        print("UC_MEM_READ_AFTER of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    return False

def show_registers(mu: Uc):
    print(f"""
            RAX: {hex(mu.reg_read(UC_X86_REG_RAX))}
            RBX: {hex(mu.reg_read(UC_X86_REG_RBX))}
    (arg 4) RCX: {hex(mu.reg_read(UC_X86_REG_RCX))}
    (arg 3) RDX: {hex(mu.reg_read(UC_X86_REG_RDX))}
    (arg 2) RSI: {hex(mu.reg_read(UC_X86_REG_RSI))}
    (arg 1) RDI: {hex(mu.reg_read(UC_X86_REG_RDI))}
            RBP: {hex(mu.reg_read(UC_X86_REG_RBP))}
            RSP: {hex(mu.reg_read(UC_X86_REG_RSP))}
            RIP: {hex(mu.reg_read(UC_X86_REG_RIP))}
    (arg 5) R8:  {hex(mu.reg_read(UC_X86_REG_R8))}
    (arg 6) R9:  {hex(mu.reg_read(UC_X86_REG_R9))}
            R10: {hex(mu.reg_read(UC_X86_REG_R10))}
            R11: {hex(mu.reg_read(UC_X86_REG_R11))}
            R12: {hex(mu.reg_read(UC_X86_REG_R12))}
            R13: {hex(mu.reg_read(UC_X86_REG_R13))}
            R14: {hex(mu.reg_read(UC_X86_REG_R14))}
            R15: {hex(mu.reg_read(UC_X86_REG_R15))}
            """)
    
def hook_code(mu: Uc, address: int, size: int, user_data):
    if address > 0x800000 and address < 0x900000:
        raise Exception("DEAD")
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' % (address, size))


def main():
    binary = load_binary()
    binary = get_x64_slice(binary)
    mu = start_unicorn()
    map_macho_binary(mu, binary)

    create_stack(mu)
    create_heap(mu)

    mu.mem_map(DEAD_BIND, 0x1000)
    mu.mem_write(DEAD_BIND, (DEAD_BIND + 8).to_bytes(8, "little"))

    #return

    # Create a return address
    mu.mem_map(STOP_ADDRESS, 0x1000)
    mu.mem_write(STOP_ADDRESS, b"\x90" * 0x1000)

    mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    mu.hook_add(UC_HOOK_CODE, hook_code)


    try:
        nac_init(mu, b"\x00" * 10)
    except UcError as e:
        print("Error:", e)
        print("Address:", hex(mu.reg_read(UC_X86_REG_RIP)))
        print("RSP:", hex(mu.reg_read(UC_X86_REG_RSP)))
        print("RBP:", hex(mu.reg_read(UC_X86_REG_RBP)))
        # Print the instruction that caused the error
        print("Instruction:", mu.mem_read(mu.reg_read(UC_X86_REG_RIP), 16).hex())

    # push_stack(mu, STOP_ADDRESS.to_bytes(8, "little"))

    # print("Starting emulation")
    # mu.emu_start(0xb1db0, STOP_ADDRESS)
    # print("Emulation done")
    # print("Return value:", hex(mu.reg_read(UC_X86_REG_RAX)))

    #try:
    #    ret = call_function(mu, 0xb1db0, [0x1, 0x1])
    #    print("Return value:", hex(ret))
    #except UcError as e:
    #    print("Error:", e)
    #    print("Address:", hex(mu.reg_read(UC_X86_REG_RIP)))


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
