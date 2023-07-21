import jelly, hashlib, macholibre

BINARY_HASH = "e1181ccad82e6629d52c6a006645ad87ee59bd13"
BINARY_PATH = "/Users/jjtech/Downloads/IMDAppleServices"

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

def malloc_hook(j: jelly.Jelly, len: int) -> int:
    # Hook malloc
    # Return the address of the allocated memory
    print("malloc hook called with len = %d" % len)
    return j.malloc(len)

def nac_init(j: jelly.Jelly, cert: bytes):
    # Allocate memory for the cert
    cert_addr = j.malloc(len(cert))
    j._uc.mem_write(cert_addr, cert)

    # Allocate memory for the outputs
    out_validation_ctx_addr = j.malloc(8)
    out_request_bytes_addr = j.malloc(8)
    out_request_len_addr = j.malloc(8)

    # Call the function
    j.instr.call(0xb1db0, [cert_addr, len(cert), out_validation_ctx_addr, out_request_bytes_addr, out_request_len_addr])

    # Get the outputs
    validation_ctx_addr = j._uc.mem_read(out_validation_ctx_addr, 8)
    request_bytes_addr = j._uc.mem_read(out_request_bytes_addr, 8)
    request_len = j._uc.mem_read(out_request_len_addr, 8)

    request = j._uc.mem_read(request_bytes_addr, request_len)

    return validation_ctx_addr, request

def hook_code(uc, address: int, size: int, user_data):
    if address > 0x800000 and address < 0x900000:
        raise Exception("DEAD")
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' % (address, size))

def memset_chk(j: jelly.Jelly, dest: int, c: int, len: int, destlen: int):
    print("memset_chk called with dest = 0x%x, c = 0x%x, len = 0x%x, destlen = 0x%x" % (dest, c, len, destlen))
    j._uc.mem_write(dest, bytes([c]) * len)
    return 0

def main():
    binary = load_binary()
    binary = get_x64_slice(binary)
    # Create a Jelly object from the binary
    j = jelly.Jelly(binary)
    hooks = {
        "_malloc": malloc_hook,
        "___stack_chk_guard": lambda: 0,
        "___memset_chk": memset_chk,
    }
    j.setup(hooks)
    j._uc.hook_add(jelly.unicorn.UC_HOOK_CODE, hook_code)
    nac_init(j, b"Hello, world!")



if __name__ == "__main__":
    main()
    
    

