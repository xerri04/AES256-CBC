CC = gcc
RM = /bin/rm

all: \
  encrypt \
  decrypt \

encrypt: encrypt.c lib/aes.c
	$(CC) -o encrypt encrypt.c lib/aes.c -lsodium

decrypt: decrypt.c lib/aes.c
	$(CC) -o decrypt decrypt.c lib/aes.c -lsodium

clean:
	-$(RM) -rf encrypt
	-$(RM) -rf decrypt
	-$(RM) -rf decrypted.key
	-$(RM) -rf public.key.hacklab