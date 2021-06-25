from capstone import *
from pwn import *
import lief, os, logging, struct

logging.basicConfig(level="DEBUG")
main_address = 0x400897

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
    binary = lief.parse('binary/dokodemo2')
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

    shellcode = [0x41, 0x54, 0x6a, 0x39, 0x5f, 0x55, 0x53, 0x48, 0x81, 0xec, 0xf0, 0x0, 0x0, 0x0, 0xe8, 0xeb, 0x0, 0x0, 0x0, 0x85, 0xdb, 0x75, 0x27, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x31, 0xd2, 0x31, 0xf6, 0x6a, 0x65, 0x5f, 0x31, 0xc0, 0xe8, 0xd4, 0x0, 0x0, 0x0, 0x6a, 0x12, 0x5a, 0x31, 0xf6, 0x6a, 0x3e, 0x5f, 0x31, 0xc0, 0xe8, 0xc5, 0x0, 0x0, 0x0, 0xe9, 0xb4, 0x0, 0x0, 0x0, 0x48, 0x8d, 0x6c, 0x24, 0xc, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x53, 0x5e, 0x55, 0x5a, 0x6a, 0x3d, 0x5f, 0x31, 0xc0, 0xe8, 0xa8, 0x0, 0x0, 0x0, 0x4c, 0x8d, 0x64, 0x24, 0x10, 0x80, 0x7c, 0x24, 0xc, 0x7f, 0xf, 0x85, 0x80, 0x0, 0x0, 0x0, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x53, 0x5a, 0x6a, 0x18, 0x5e, 0x6a, 0x65, 0x5f, 0x31, 0xc0, 0xe8, 0x84, 0x0, 0x0, 0x0, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x55, 0x5a, 0x53, 0x5e, 0x6a, 0x3d, 0x5f, 0x31, 0xc0, 0xe8, 0x71, 0x0, 0x0, 0x0, 0x31, 0xc9, 0x41, 0x54, 0x41, 0x58, 0x53, 0x5a, 0x6a, 0xc, 0x5e, 0x6a, 0x65, 0x5f, 0x31, 0xc0, 0xe8, 0x5c, 0x0, 0x0, 0x0, 0x48, 0x8b, 0x84, 0x24, 0x88, 0x0, 0x0, 0x0, 0x48, 0x83, 0xe8, 0x38, 0x48, 0x83, 0xf8, 0x3, 0x77, 0xa7, 0x41, 0x54, 0x41, 0x58, 0x31, 0xc9, 0x53, 0x5a, 0x6a, 0xd, 0x5e, 0x6a, 0x65, 0x5f, 0x31, 0xc0, 0x48, 0xc7, 0x84, 0x24, 0x88, 0x0, 0x0, 0x0, 0xe7, 0x0, 0x0, 0x0, 0x48, 0xc7, 0x84, 0x24, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xe8, 0x1d, 0x0, 0x0, 0x0, 0xe9, 0x75, 0xff, 0xff, 0xff, 0x31, 0xf6, 0x6a, 0x3c, 0x5f, 0x31, 0xc0, 0xe8, 0xc, 0x0, 0x0, 0x0, 0x48, 0x81, 0xc4, 0xf0, 0x0, 0x0, 0x0, 0x5b, 0x5d, 0x41, 0x5c, 0xc3, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xca, 0x4d, 0x89, 0xc2, 0x4d, 0x89, 0xc8, 0xf, 0x5, 0xc3, 0xff]
    main_code = content[:(patch_end-patch_start+1)] # assembly replaced by "jmp shellcode"
    ret_content = asm("push 0x%x" % (patch_end + 1)) 
    ret_code = list(struct.unpack('B'*len(ret_content), ret_content))  # assembly "jmp main+0xnn"
    shellcode = main_code + ret_code + shellcode
    binary.patch_address(physical_address, shellcode)


    binary.write("binary/dokodemo2_patched")
    os.system("chmod +x ./binary/dokodemo2_patched")

if __name__ == "__main__":
    main()