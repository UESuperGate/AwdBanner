.global asm_syscall 

.global _start

_start:
    jmp sandbox

asm_syscall:
    mov    %rdi,%rax
    mov    %rsi,%rdi
    mov    %rdx,%rsi
    mov    %rcx,%rdx
    mov    %r8,%r10
    mov    %r9,%r8
    syscall 
    ret   
