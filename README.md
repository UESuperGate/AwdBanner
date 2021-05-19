# AWDBanner

You can inject your codes into the binary, so that you can:

- Hook the selected syscall.
- Capture the I/O information.
- ...

## Environment

```shell
sudo pip3 install pwntools lief
```

## Usage

```shell
./build.sh <binary_to_be_patched>
```

And the patched file will be at the same directory as the original file.

## File Descriptions

### build.sh

The entry of this tool. It compiles the shellcode, and execute modify.py.

### modify.py

Inject binary with shellcode, with which we can launch sandbox before the main logic starts.