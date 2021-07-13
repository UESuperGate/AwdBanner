from capstone import *
from pwn import *
import lief, os, logging, struct, sys
context.arch="amd64"

# logging.basicConfig(level="INFO")

"""
    Replace note segment with LOAD segment.
    We can specify permissions of it.
"""
def add_segment(binary):
    segment = lief.ELF.Segment()
    segment.type = lief.ELF.SEGMENT_TYPES.LOAD
    segment.add(lief.ELF.SEGMENT_FLAGS.X)
    segment.add(lief.ELF.SEGMENT_FLAGS.R)
    segment.content = [0x0 for i in range(0x1000)]
    segment = binary.replace(segment, binary[lief.ELF.SEGMENT_TYPES.NOTE])
    return segment.physical_address


def main():
    if len(sys.argv) != 3:
        print("Usage: python modify.py binary shellcode")
        exit()
    else:
        binary_path = sys.argv[1]
        shellcode_path = sys.argv[2]

    binary = lief.parse(binary_path)

    # get entrypoint
    start_address = binary.header.entrypoint

    # add a new segment
    physical_address = add_segment(binary)
    logging.debug("new_segment address: " + hex(physical_address))

    # change the entrypoint to new segment
    binary.header.entrypoint = physical_address  

    # read shellcode from file
    with open(shellcode_path, "rb") as f:  
        shellcode = [each for each in f.read()]

    # a shellcode to redirect ret_address to _start
    ret_content = asm("""   
        call $+5
        pop rax
        sub rax, 0x5
        sub rax, {}
        push rax
    """.format(hex(physical_address-start_address))) 
    ret_code = list(struct.unpack('B'*len(ret_content), ret_content))  # assembly "jmp main+0xnn"
    shellcode = ret_code + shellcode

    # patch address
    binary.patch_address(physical_address, shellcode)

    # patch binary
    patched_path = binary_path + ".patched"
    binary.write(patched_path)

if __name__ == "__main__":
    main()