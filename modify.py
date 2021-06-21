from pwn import *
import lief, os, logging, struct, sys

context.arch = "amd64"
logging.basicConfig(level="DEBUG")

def bytes2list(shellcode):
    return list(struct.unpack('B' * len(shellcode), shellcode))


def main():
    if len(sys.argv) != 3:
        print("Usage: python modify.py binary shellcode")
        # exit()
        binary_path = "/home/mrh929/git/AwdBanner/binary/lonelywolf/lonelywolf"
        shellcode_path = "/home/mrh929/git/AwdBanner/shellcode"
    else:
        binary_path = sys.argv[1]
        shellcode_path = sys.argv[2]

    binary = lief.parse(binary_path)
    elf = ELF(binary_path)

    # get entrypoint
    start_address = binary.header.entrypoint
    start_sc = binary.get_content_from_virtual_address(start_address, 0x30)
    logging.debug("detect entrypoint: %s" % hex(start_address))

    # get eh_frame_hdr
    eh_frame_hdr = binary.get_section(".eh_frame_hdr")
    eh_frame = binary.get_section(".eh_frame")
    eh_frame_hdr_address = eh_frame_hdr.virtual_address
    logging.debug("detect eh_frame_hdr: %s" % hex(eh_frame_hdr_address))

    offset = eh_frame_hdr_address - (start_address + 5)
    logging.debug("offset to eh_frame_hdr: %s" % hex(offset))

    mprotect_sc = asm("""
        call $+5
        pop rdi  
        
        push {}
        pop rsi
        add rdi, rsi
        push rdi
        and rdi, 0xFFFFFFFFFFFFF000

        push 7
        pop rdx

        push 0x1000
        pop rsi

        push SYS_mprotect
        pop rax
        syscall
        ret
    """.format(hex(offset)))

    logging.debug('length of mprotect_shellcode: %s' % hex(len(mprotect_sc)))
    binary.patch_address(start_address, bytes2list(mprotect_sc))

    start_disass = disasm(elf.read(elf.entry, 0x30), byte=False)
    print(start_disass)

    patched_disasm = ""
    for line in start_disass.splitlines():
        patched_disasm += line[line.find(":") + 1:] + "\n"

    patched_disasm = patched_disasm.replace(
        'rip', 'rip + %s' % hex(eh_frame_hdr_address - start_address))
    print(patched_disasm)

    patched_sc = asm(patched_disasm)
    main_sc = asm("call $+%s" % hex(5+len(patched_sc))) + patched_sc

    sandbox_sc = main_sc
    sandbox_sc += asm("""
    
    
    """)

    logging.debug("length of sandbox_shellcode: %s" % hex(len(sandbox_sc)))

    allowed_length = eh_frame.virtual_address + eh_frame.size - eh_frame_hdr.virtual_address
    logging.debug("allowed length: %s" % hex(allowed_length))

    assert (allowed_length > len(sandbox_sc))

    binary.patch_address(eh_frame_hdr_address, bytes2list(sandbox_sc))

    # patch binary
    patched_path = binary_path + ".patched"
    binary.write(patched_path)


if __name__ == "__main__":
    main()