#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aes.h"

#define CBC 1
#define CHUNK_SIZE 1024 + 16

uint8_t decrypted[CHUNK_SIZE - 16];
uint8_t ciphertext[CHUNK_SIZE];
uint8_t decrypted_len;

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

    // Reading key
    uint8_t key[32]; // Properly allocate the key buffer
    fread(key, 1, sizeof(key), PMK_Key); // Use key instead of uninitialized variable

    // Write the nonce to the output file.
    uint8_t nonce[16]; // Properly allocate the nonce buffer
    fread(nonce, sizeof(uint8_t), sizeof(nonce), hacklab_in);

    AES_init_ctx_iv(&ctx, key, nonce);

    printf("key:\n");
    phex(key);
    printf("\n");

    printf("nonce:\n");
    phex(nonce);
    printf("\n");

    size_t ciphertext_len;

    // Continue processing the file in CHUNK_SIZE blocks
    while ((ciphertext_len = fread(ciphertext, 1, CHUNK_SIZE, hacklab_in)))
    {
        AES_init_ctx_iv(&ctx, key, nonce);
        AES_CBC_decrypt_buffer(&ctx, ciphertext, ciphertext_len);

        fwrite(ciphertext, 1, ciphertext_len, fp_decrypt);
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
