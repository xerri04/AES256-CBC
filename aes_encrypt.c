#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aes.h"

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
        return 1; // Return 1 instead of 0 on error
    }

    // Reading key
    uint8_t key[32]; // Properly allocate the key buffer
    fread(key, 1, sizeof(key), PMK_Key); // Use key instead of uninitialized variable

    // Write the nonce to the output file.
    uint8_t nonce[16]; // Properly allocate the nonce buffer
    randombytes_buf(nonce, sizeof(nonce));
    fwrite(nonce, sizeof(uint8_t), sizeof(nonce), fp_out); // Use sizeof(uint8_t) for consistency

    uint8_t MESSAGE[CHUNK_SIZE];

    AES_init_ctx_iv(&ctx, key, nonce);

    printf("key:\n");
    phex(key);
    printf("\n");

    printf("nonce:\n");
    phex(nonce);
    printf("\n");

    size_t bytes_read;

    while ((bytes_read = fread(MESSAGE, 1, CHUNK_SIZE, fp_in)))
    {
        AES_init_ctx_iv(&ctx, key, nonce);
        AES_CBC_encrypt_buffer(&ctx, MESSAGE, bytes_read);
        fwrite(MESSAGE, 1, bytes_read, fp_out);
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