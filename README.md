# AWDBanner

You can inject your codes into the binary, so that you can:

- Hook the selected syscall. (version 1 & 2)
- Capture the I/O information. (only verison 1)
- ...

**Why there are two versions?**

We found that starting a sandbox by modifying the prot of a segment and injecting shellcode into it is not working in AWD matches (because checker will check the size and header of a binary).

Therefore, version2 is born to bypass the binary checker only by changing some assembly in **text** section and **eh_frame** section.

## Environment

```shell
pip3 install pwntools lief
```

## Usage

### v1

Due to the modification of the segment permissions and the size of the binary, this modification method cannot pass most of the checker's inspections, but it has richer functions and can monitor traffic.

```shell
./build.sh <binary_to_be_patched>
```

### v2

This version only modifies the text section and eh_frame section, which can bypass the inspection of more checkers, but the function is relatively single and can only be used as a sandbox.

```shell
python3 modify.py <binary_to_be_patched>
```

And the patched file will be at the same directory as the original file.

### TODO

- [x] x64 support
- [ ] smaller shellcode
- [ ] syscall self-selection
- [ ] x86/arm/arm64 support