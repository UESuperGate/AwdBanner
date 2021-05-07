#!/bin/bash

binary_path="$1"

if [ ! -f "$1" ]; then
    echo "Usage: ./build.sh binary"
    exit
fi

gcc -c  awdDefender.s ptrace_demo.c -fno-stack-protector
ld awdDefender.o ptrace_demo.o
objcopy -O binary -j .text a.out shellcode
rm a.out
rm *.o

python modify.py ${binary_path} shellcode
chmod +x "${binary_path}.patched"