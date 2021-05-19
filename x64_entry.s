.global asm_syscall 

.global _start, before_call, readbanner, writebanner, newline

_start:
    jmp sandbox

before_call:
.asciz "syscall detected!\n"
readbanner:
.asciz "[READ] "
writebanner:
.asciz "[WRITE] "

asm_syscall:
    mov    %rdi,%rax
    mov    %rsi,%rdi
    mov    %rdx,%rsi
    mov    %rcx,%rdx
    mov    %r8,%r10
    mov    %r9,%r8
    syscall 
    ret   
    