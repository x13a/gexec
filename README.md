# exec-guard

Binary execution guard.

- Create in-memory file descriptor via memfd_create()
- Loop
    - Read a chunk of executable
    - Write to SHA256 hasher
    - Write to in-memory file descriptor
- Checksum
- Exec via fexecve()

## Installation
```sh
$ make
$ sudo make install
```
or
```sh
$ brew tap x13a/tap
$ brew install x13a/tap/exec-guard
```

## Usage
```text
exec-guard [-h|V] [-e SHA256] [-s SHA256] <EXECUTABLE_PATH> [<SCRIPT_PATH>] [..ARGS]

[-h] * Print help and exit
[-V] * Print version and exit
[-e] * Executable hash
[-s] * Script hash
```

## Example

To check and exec binary:
```sh
$ exec-guard -e "68c1f856c32e521cc04d3d8f28a548c3e66e26b64d25ee10e907dd9b68fdc1c9" /usr/bin/uname -a
```

To check and exec script:
```sh
$ exec-guard -e "EXECUTABLE_SHA256" -s "SCRIPT_SHA256" /usr/bin/python /path/to/file.py
```
