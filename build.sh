gcc -c  awdDefender.s ptrace_demo.c -fno-stack-protector
ld awdDefender.o ptrace_demo.o
objcopy -O binary -j .text a.out shellcode
rm a.out
rm *.o 
