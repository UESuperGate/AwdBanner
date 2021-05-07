#!/bin/bash

binary_path="$1"
arch="x64"

if [ ! -f "binary_path" ]; then
    echo "Usage: ./build.sh binary"
    exit
fi

gcc -c ${arch}_entry.s banner.c -fno-stack-protector
ld ${arch}_entry.o banner.o
objcopy -O binary -j .text a.out shellcode
rm a.out
rm *.o

python modify.py "${binary_path}" shellcode
chmod +x "${binary_path}.patched"