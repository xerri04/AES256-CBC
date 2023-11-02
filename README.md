# AES256-CBC
AES256-CBC C with padding implementation with tiny AES, which generates a random nonce that is safe to use for cryptography padding implementation

The current repository contains codes which measures:

1. CPU Cycles per Bytes
2. CPU Time
3. Wall Time

To compile both encrypt.c & decrypt.c, simply run the Makefile:

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
