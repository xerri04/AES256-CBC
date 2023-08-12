CC = gcc
RM = /bin/rm

ESOURCES = lib/aes.c lib/encrypt.c
DSOURCES = lib/aes.c lib/decrypt.c

# Paths for executables and output files
EOUTPUT = lib/encrypt
DOUTPUT = lib/decrypt

.PHONY: all speed shared clean

all: $(EOUTPUT) $(DOUTPUT)

# Build the encrypt and decrypt executables
$(EOUTPUT): $(ESOURCES)
	$(CC) -o $@ $(ESOURCES) -lsodium

$(DOUTPUT): $(DSOURCES)
	$(CC) -o $@ $(DSOURCES) -lsodium

# Create a static library named libmylib.a
aes.a: $(ESOURCES) $(DSOURCES)
	ar rcs $@ $(ESOURCES) $(DSOURCES)

# Add the aes.a library to the dependencies for the encrypt and decrypt executables
$(EOUTPUT): aes.a
$(DOUTPUT): aes.a

clean:
	-$(RM) -rf $(EOUTPUT)
	-$(RM) -rf $(DOUTPUT)
	-$(RM) -rf lib/decrypted.key
	-$(RM) -rf lib/public.key.hacklab
	-$(RM) -rf aes.a