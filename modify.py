from capstone import *
from pwn import *
import lief, os, logging, struct, sys

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
    if len(sys.argv) != 4:
        print("Usage: python modify.py binary shellcode start_addr")
        exit()
        binary_path = "binary/dokodemo2"
        shellcode_path = "shellcode"
        main_address = 0x400897

    else:
        binary_path = sys.argv[1]
        shellcode_path = sys.argv[2]
        main_address = int(sys.argv[3], 16)

    binary = lief.parse(binary_path)
    physical_address = add_segment(binary)
    logging.debug("new_segment address: " + hex(physical_address))

    content = binary.get_content_from_virtual_address(main_address, 0x20)
    print([hex(each) for each in content])

    code = struct.pack('B'*0x20, *content)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    patch_start = main_address
    patch_end = patch_start
    for (address, size, mnemonic, op_str) in md.disasm_lite(code, 0):
        print("0x%x 0x%x:\t%s\t%s" %(address, address + main_address, mnemonic, op_str))
        if address > 4:
            patch_end += address - 1
            logging.debug("patch_start = 0x%x" % patch_start)
            logging.debug("patch_end = 0x%x" % patch_end)
            logging.debug("patch_length = 0x%x" % (patch_end-patch_start+1))
            break
    
    assert(patch_start != patch_end)

    jmp_shellcode_content = asm("jmp 0x%x" % physical_address, vma=patch_start) 
    jmp_shellcode_code = list(struct.unpack('B'*len(jmp_shellcode_content), jmp_shellcode_content))  # assembly "jmp shellcode"    
    binary.patch_address(patch_start, jmp_shellcode_code)


    with open(shellcode_path, "rb") as f:
        shellcode = [each for each in f.read()]

    main_code = content[:(patch_end-patch_start+1)] # assembly replaced by "jmp shellcode"
    ret_content = asm("push 0x%x" % (patch_end + 1)) 
    ret_code = list(struct.unpack('B'*len(ret_content), ret_content))  # assembly "jmp main+0xnn"
    shellcode = main_code + ret_code + shellcode
    binary.patch_address(physical_address, shellcode)


    patched_path = binary_path + ".patched"
    binary.write(patched_path)
    # os.system("chmod +x ./binary/dokodemo2_patched")

if __name__ == "__main__":
    main()