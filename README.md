# AES256-CBC
An implementation of AES-256-CBC with padding using Tiny AES, which generates a random nonce that is safe to use for cryptography.

This repository contains code that measures:

1. CPU Cycles per Bytes
2. CPU Time
3. Wall Time

To compile both encrypt.c and decrypt.c, simply run the Makefile:

```
make all
```

Simply clean by running:

```
make clean
```

# Usage

Usage of encrypt.c:

```
./encrypt <plaintext file> <encrypted file> <key file>
```

Usage of decrypt.c:

```
./decrypt <encrypted file> <plaintext file> <key file>
```
