#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aes.h"
#include "pkcs7_padding.c"

#define CBC 1
#define CHUNK_SIZE 1024

static void phex(const uint8_t *str);

int main(void)
{
    if (sodium_init() < 0)
    {
        printf("panic! the library couldn't be initialized; it is not safe to use");
        return 1;
    }

    struct AES_ctx ctx;

    FILE *fp_in, *fp_out, *PMK_Key;

    fp_in = fopen("test.key", "rb");
    if (fp_in == NULL)
    {
        printf("Error opening key to encrypt.\n");
        return 1;
    }

    fp_out = fopen("public.key.hacklab", "wb");
    if (fp_out == NULL)
    {
        printf("Error opening file for ciphertext.\n");
        return 1;
    }

    // Open the PMK key.
    PMK_Key = fopen("PMK.key", "rb");
    if (PMK_Key == NULL)
    {
        printf("Error opening PMK key\n");
        return 1;
    }

    char key[32];
    char nonce[16]; 
    uint8_t MESSAGE[CHUNK_SIZE];
    uint8_t i;                               

    randombytes_buf(nonce, sizeof(nonce));

    size_t klen = fread(key, 1, sizeof(key), PMK_Key);
    fwrite(nonce, sizeof(char), sizeof(nonce), fp_out);

    printf("key:\n");
    phex((const uint8_t *)key);
    printf("\n");

    printf("nonce:\n");
    phex((const uint8_t *)nonce);
    printf("\n");

    // Proper length of key and nonce
    int klenu = 32;
    int nlenu = 16;

    // Make the uint8_t arrays
    uint8_t hexarray[CHUNK_SIZE];
    uint8_t kexarray[32];
    uint8_t nexarray[16];
    
    // Initialize them with zeros
    memset( hexarray, 0, sizeof(hexarray) );
    memset( kexarray, 0, sizeof(kexarray) );
    memset( nexarray, 0, sizeof(nexarray) );
    
    // Fill the uint8_t arrays
    for (size_t i = 0; i < CHUNK_SIZE; i++) {
        hexarray[i] = MESSAGE[i];
    }

    for (size_t i = 0; i < klen; i++) {
        kexarray[i] = (uint8_t)key[i];
    }
    
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nexarray[i] = (uint8_t)nonce[i];
    }

    size_t bytes_read;

    while ((bytes_read = fread(MESSAGE, 1, CHUNK_SIZE, fp_in)))
    {
        // Proper length of message
        size_t mlenu = bytes_read;
        if (bytes_read % 16) {
            mlenu += 16 - (bytes_read % 16);
        }

        // Start the encryption
        AES_init_ctx_iv(&ctx, kexarray, nexarray);
        
        // Encrypt
        AES_CBC_encrypt_buffer(&ctx, MESSAGE, mlenu);
        fwrite(MESSAGE, 1, mlenu, fp_out);
    }

    fclose(fp_in);
    fclose(fp_out);
    fclose(PMK_Key);

    return 0;
}

// prints string as hex
static void phex(const uint8_t *str) // Use const for read-only access
{
    uint8_t len = 16;

    for (unsigned char i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}
