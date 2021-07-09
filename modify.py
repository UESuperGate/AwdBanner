#!/usr/bin/python3
from pwn import *
from os import chmod
import lief

context.arch = "amd64"


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 modify.py binary")
        exit()
    else:
        binary_path = sys.argv[1]

    # get binary
    binary = lief.parse(binary_path)
    elf = ELF(binary_path, checksec=False)
    log.success("parse elf success!")

    # get sections
    eh_frame_hdr = binary.get_section(".eh_frame_hdr")
    eh_frame = binary.get_section(".eh_frame")

    # This part is to trigger syscall 'mprotect'
    #   to let .eh_frame and .eh_frame_hdr sections executable.
    # Then we can execute shellcode on them.
    log.info("generating shellcode...")
    mprotect_shellcode = asm("""
        call $+5
        pop rdi  
        
        push {}
        pop rsi
        add rdi, rsi
        push rdi
        and rdi, 0xFFFFFFFFFFFFF000  # mprotect address

        push 5
        pop rdx # prot = rx

        push 0x1000
        pop rsi # size = 0x1000

        push SYS_mprotect
        pop rax
        syscall # syscall(mprotect)
        ret
    """.format(hex(eh_frame_hdr.virtual_address - (elf.entry + 5))))

    # This part is to create shellcode to execute function sandbox.
    # And then let the program return to start for allocation.
    # I use asm and disasm to change the offset of the shellcode.
    start_disasm = disasm(elf.read(elf.entry, 0x30), byte=False, vma=elf.entry)
    start_disasm_patched = ""
    for line in start_disasm.splitlines():
        start_disasm_patched += line[line.find(":") + 1:] + "\n"

    start_disasm_patched = start_disasm_patched.replace(
        'rip', 'rip + %s' %
        hex(elf.entry -
            (eh_frame_hdr.virtual_address + 5)))  # the length of 'call' is 5
    start_shellcode_patched = asm(start_disasm_patched,
                                  vma=eh_frame_hdr.virtual_address + 5)

    sandbox_shellcode = asm(
        "call $+%s" %
        hex(5 + len(start_shellcode_patched))) + start_shellcode_patched
    sandbox_disasm = '''
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
        jnz     EXT
        mov     edx, ebp
        push    0x18
        pop     rsi
        push    0x65
        pop     rdi
        xor     r8, r8
        xor     rcx,rcx
        call    asm_syscall
        mov     rdx, r12
        mov     esi, ebp
        push    61
        pop     rdi
        xor     rcx,rcx
        xor     r8,r8
        call    asm_syscall
        mov     edx, ebp
        mov     r8, r13
        push    0xc
        pop     rsi
        push    0x65
        pop     rdi
        xor     rcx,rcx
        call    asm_syscall
        mov     rax, [rsp+0x80]
        cmp rax,335
        ja EXT
        
        lea     rdx, [rax-0x38]
        cmp     rdx, 3
        jbe     KILL
        cmp     rax, 2
        jnz     LOOP
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
    EXT:
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
    sandbox_shellcode += asm(sandbox_disasm)
    log.success("shellcode generated!")

    maximum_write_length = eh_frame.virtual_address + eh_frame.size - eh_frame_hdr.virtual_address
    log.info("sandbox shellcode length: %6s" % hex(len(asm(sandbox_disasm))))
    log.info("total length: %6s" % hex(len(sandbox_shellcode)))
    log.info("allowed length: %6s" % hex(maximum_write_length))

    # If shellcode is too long, exit.
    if maximum_write_length < len(asm(sandbox_disasm)):
        log.error("shellcode is too long!")
        exit()

    # Pad all the rest of the bytes with b'\x90'.
    sandbox_shellcode = sandbox_shellcode.ljust(maximum_write_length, b'\x90')

    # Patch elf and save it.
    log.info("saving patches...")
    elf.write(elf.entry, mprotect_shellcode)
    elf.write(eh_frame_hdr.virtual_address, sandbox_shellcode)
    elf.save(binary_path + ".patched")
    # os.system("chmod +x " + binary_path + ".patched")
    chmod(binary_path + ".patched", 0o755)
    log.success("patch success!")


if __name__ == "__main__":
    main()

# log func for debug
'''
    LOG:
        push    rax
        mov     rsi,rsp
        xor     rax,rax
        inc     rax
        xor     rdi,rdi
        inc     rdi
        mov     rdx,0x8
        mov rdx,rax
        syscall
        pop rax
        ret
'''