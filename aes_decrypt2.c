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

    FILE *hacklab_in, *fp_decrypt, *PMK_Key;

    hacklab_in = fopen("public.key.hacklab", "rb");
    if (hacklab_in == NULL)
    {
        printf("Error opening key to encrypt.\n");
        return 1;
    }

    fp_decrypt = fopen("decrypted.key", "wb");
    if (fp_decrypt == NULL)
    {
        printf("Error opening file for ciphertext.\n");
        return 1;
    }

    // Open the PMK key.
    PMK_Key = fopen("PMK.key", "rb");
    if (PMK_Key == NULL)
    {
        printf("Error opening PMK key\n");
        return 1; // Return 1 instead of 0 on error
    }

    char key[32];
    char nonce[16]; 
    uint8_t decryptedtext[CHUNK_SIZE];
    uint8_t i;                               

    size_t klen = fread(key, 1, sizeof(key), PMK_Key);
    fread(nonce, sizeof(uint8_t), sizeof(nonce), hacklab_in);

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
        hexarray[i] = decryptedtext[i];
    }

    for (size_t i = 0; i < klen; i++) {
        kexarray[i] = (uint8_t)key[i];
    }
    
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nexarray[i] = (uint8_t)nonce[i];
    }

    size_t decryptedtext_len;

    // Continue processing the file in CHUNK_SIZE blocks
    while ((decryptedtext_len = fread(decryptedtext, 1, CHUNK_SIZE, hacklab_in)))
    {
        AES_init_ctx_iv(&ctx, kexarray, nexarray);
        AES_CBC_decrypt_buffer(&ctx, decryptedtext, decryptedtext_len);
        fwrite(decryptedtext, 1, decryptedtext_len, fp_decrypt);
    }

    fclose(hacklab_in);
    fclose(fp_decrypt);
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
