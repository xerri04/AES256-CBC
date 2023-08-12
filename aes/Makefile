CC = gcc
RM = /bin/rm

ESOURCES = lib/aes.c lib/encrypt.c
DSOURCES = lib/aes.c lib/decrypt.c

# Paths for executables and output files
EOUTPUT = lib/encrypt
DOUTPUT = lib/decrypt

.PHONY: all clean

all: $(EOUTPUT) $(DOUTPUT)

# Build the encrypt and decrypt executables
$(EOUTPUT): $(ESOURCES)
	$(CC) -o $@ $(ESOURCES) -lsodium

$(DOUTPUT): $(DSOURCES)
	$(CC) -o $@ $(DSOURCES) -lsodium

clean:
	-$(RM) -rf $(EOUTPUT)
	-$(RM) -rf $(DOUTPUT)
	-$(RM) -rf lib/decrypted.key
	-$(RM) -rf lib/public.key.hacklab