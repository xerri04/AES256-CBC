# AES256-CBC
AES256-CBC encryption implementation with tiny aes c and pkcs7 padding.

To compile encryption and decryption code:
```
gcc encrypt.c aes.c -o encrypt -lsodium
```
```
gcc decrypt.c aes.c -o decrypt -lsodium
```

## Makefile
To run AES256-CBC, simply run the Makefile:

```
make all
```

To clean the files, run the Makefile:

```
make clean
```

## Test Speed
1. CPU Cycles per bytes
2. CPU Time
3. Wall Time