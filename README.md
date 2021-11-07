# gexec

Execution guard.

- Create in-memory file descriptor via memfd_create()
- Check minisign or sha256
- Exec via fexecve()

## Installation
```sh
$ make
$ sudo make install
```
or
```sh
$ brew tap x13a/tap
$ brew install x13a/tap/gexec
```

## Usage
```text
gexec [-h|V] [-x] [-P PUBLIC_KEY]
      [-E SIG_PATH] [-e SHA256]
      [-S SIG_PATH] [-s SHA256]
      <EXECUTABLE_PATH> [<SCRIPT_PATH>] [..ARGS]

[-h] * Print help and exit
[-V] * Print version and exit
[-x] * Use execve()
[-P] * Minisign base64 public key
[-E] * Executable signature path
[-e] * Executable hash
[-S] * Script signature path
[-s] * Script hash
```

## Example

To check and exec binary (sha256):
```sh
$ gexec -e "68c1f856c32e521cc04d3d8f28a548c3e66e26b64d25ee10e907dd9b68fdc1c9" /usr/bin/uname -a
```

To check and exec script (sha256):
```sh
$ gexec -x -s "SCRIPT_SHA256" /usr/bin/python /path/to/file.py
```

To check and exec binary (minisign):
```sh
$ gexec -P "MINISIGN_BASE64_PUBLIC_KEY" /usr/bin/true
```

To exec binary from memory:
```sh
$ cat /usr/bin/uname | gexec -
```

To check and exec script from memory (sha256):
```sh
$ cat /path/to/file.py | gexec -x -s "SCRIPT_SHA256" /usr/bin/python -
```
