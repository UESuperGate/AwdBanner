from pwn import *
import sys

from pwnlib.util.fiddling import hexdump

if len(sys.argv) < 2:
    print("Usage: python readLog logFile")

with open(sys.argv[1], "rb") as f:
    while True:
        type = f.read(1)
        if len(type) == 0:
            break
        
        type = u8(type)
        length = u64(f.read(8))

        if type == 0:
            print("[READ {}]".format(length))
        elif type == 1:
            print("[WRITE {}]".format(length))
        else:
            print("Unknown type")
            exit(-1)

        print(hexdump(f.read(length)))