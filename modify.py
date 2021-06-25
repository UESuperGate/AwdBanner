from pwn import *
import lief, os, logging, struct, sys

context.arch = "amd64"
#logging.basicConfig(level="DEBUG")

# def bytes2list(shellcode):
#     return list(struct.unpack('B' * len(shellcode), shellcode))

def patch_file(file, offset, data):
    file.seek(offset)
    file.write(data)
    info("patched %6s bytes at %6s" % (hex(len(data)), hex(offset)))

def patch_address(file, section, address, data):
    base_address = section.virtual_address
    section_size = section.size
    # assert(base_address <= address)

    print(hex(address + len(data)), hex(base_address + section_size))
    # assert(address + len(data) <= base_address + section_size)

    patch_file(file, section.file_offset + address - section.virtual_address, data)

def main():
    if len(sys.argv) != 2:
        print("Usage: python modify.py binary")
        # exit()
        binary_path = "/home/mrh929/test/test/test"
    else:
        binary_path = sys.argv[1]

    binary = lief.parse(binary_path)
    ori_file = open(binary_path, 'rb')
    patched_path = binary_path + ".patched"
    patched_file = open(patched_path, 'wb')
    patched_file.write(ori_file.read())
    ori_file.close()

    elf = ELF(binary_path, checksec=False)

    # get entrypoint
    start_address = binary.header.entrypoint

    # get eh_frame_hdr
    eh_frame_hdr = binary.get_section(".eh_frame_hdr")
    eh_frame = binary.get_section(".eh_frame")
    text = binary.get_section(".text")

    eh_frame_hdr_address = eh_frame_hdr.virtual_address
    #logging.debug("detect eh_frame_hdr: %s" % hex(eh_frame_hdr_address))

    offset = eh_frame_hdr_address - (start_address + 5)
    #logging.debug("offset to eh_frame_hdr: %s" % hex(offset))

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

    #logging.debug('length of mprotect_shellcode: %s' % hex(len(mprotect_sc)))
    patch_address(patched_file, text, start_address, mprotect_sc)



    start_disass = disasm(elf.read(elf.entry, 0x30), byte=False)
    print("start_disass")
    print(start_disass)

    patched_disasm = ""
    for line in start_disass.splitlines():
        patched_disasm += line[line.find(":") + 1:] + "\n"

    patched_disasm = patched_disasm.replace(
        'rip', 'rip + %s' % hex(start_address - (eh_frame_hdr_address + 5))) # the length of 'call' is 5
    
    patched_sc = asm(patched_disasm)

    print("\n\npatched_disasm")
    print(disasm(patched_sc))


    main_sc = asm("call $+%s" % hex(5+len(patched_sc))) + patched_sc

    sandbox_sc = main_sc
    sh='''
    sandbox:
        push    r13
        push    r12
        push    rbp
        push    rbx
        sub     rsp, 0xE8
        push 57
        pop rax
        syscall
        test    eax, eax
        jnz WATCH
        xor     edx, edx
        xor     esi, esi
        xor     r8d, r8d
        xor     ecx, ecx
        xchg    rax, rdi
        push 0x65
        pop rdi
        call    asm_syscall
        push   0x27
        pop rax
        syscall
        mov     dl, 0x12
        push 62
        pop rdi
        xchg    rax, rsi
        call    asm_syscall
        jmp DEAD
    WATCH: 
        lea     r12, [rsp+4]
        mov     rsi, rax
        mov     rbx, rax
        mov     rbp, rax
        xor     r8, r8
        xor     rcx, rcx
        mov     rdx, r12
        push    61
        pop     rdi
        lea     r13, [rsp+8]
        call    asm_syscall
    LOOP:
        cmp     byte ptr [rsp+4], 0x7F
        jnz     loc_143
        mov     edx, ebp
        push 0x18
        pop rsi
        push 0x65
        pop rdi
        xor rcx,rcx
        call    asm_syscall
        mov     rdx, r12
        mov     esi, ebp
        push 61
        pop rdi
        xor rcx,rcx
        call    asm_syscall
        mov     edx, ebp
        mov     r8, r13
        push 0xc
        pop rsi
        push 0x65
        pop rdi
        xor rcx,rcx
        call    asm_syscall
        mov     rax, [rsp+0x80]
        lea     rdx, [rax-0x38]
        cmp     rdx, 3
        jbe     short KILL
        cmp     rax, 2
        jnz     short LOOP
    KILL:
        mov     r8, r13
        xor     ecx, ecx
        mov     edx, ebx
        push 0xd
        pop rsi
        mov     qword ptr [rsp+0x78], 0
        push 0x65
        pop rdi
        mov     qword ptr [rsp+0x80], 0xE7
        call    asm_syscall
    loc_143:
        push 0x3c
        pop rdi
        call    asm_syscall
    DEAD:
        add     rsp, 0xE8
        pop     rbx
        pop     rbp
        pop     r12
        pop     r13
        ret
    asm_syscall:
        mov    rax,rdi
        mov    rdi,rsi
        mov    rsi,rdx
        mov    rdx,rcx
        mov    r10,r8
        mov    r8,r9
        syscall 
        ret
    '''
    sandbox_sc += asm(sh)
    log.warning("sandbox shellcode length: %6s" % hex(len(asm(sh))))
    #logging.debug("length of sandbox_shellcode: %s" % hex(len(sandbox_sc)))

    allowed_length = eh_frame.virtual_address + eh_frame.size - eh_frame_hdr.virtual_address
    log.warning("allowed length: %6s" % hex(allowed_length))

    assert (allowed_length > len(sandbox_sc))


    sandbox_sc = sandbox_sc.ljust(allowed_length, b'\x90')
    # binary.patch_address(eh_frame_hdr_address, bytes2list(sandbox_sc))
    patch_address(patched_file, eh_frame_hdr, eh_frame_hdr.virtual_address, sandbox_sc[:allowed_length - eh_frame.size])
    patch_address(patched_file, eh_frame, eh_frame.virtual_address, sandbox_sc[allowed_length - eh_frame.size:])

    patched_file.close()


if __name__ == "__main__":
    main()