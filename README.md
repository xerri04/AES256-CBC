# AES256-CBC
AES256-CBC encryption implementation with tiny aes c and pkcs7 padding.

To compile encryption and decryption code:
```
gcc encrypt.c -o encrypt -lsodium
```
```
gcc decrypt.c -o decrypt -lsodium
```