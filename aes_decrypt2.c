#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aes.h"
#include "pkcs7_padding.c"

#define CBC 1
#define AES_BLOCK_SIZE 16
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

    uint8_t i;
    char decryptedtext[CHUNK_SIZE];                               
    uint8_t key[32];
    uint8_t nonce[16];

    size_t bytes_read;

    fread(nonce, sizeof(char), sizeof(nonce), hacklab_in);
    fread(key, 1, sizeof(key), PMK_Key);
    
    printf("key:\n");
    phex(key);
    printf("\n");

    printf("nonce:\n");
    phex(nonce);
    printf("\n");

    while ((bytes_read = fread(decryptedtext, 1, CHUNK_SIZE, hacklab_in)))
    {
        int mlen = bytes_read;
        int mlenu = mlen;
        if (mlen % 16) {
            mlenu += 16 - (mlen % 16);
            printf("The original length of the STRING = %d and the length of the padded STRING = %d\n", mlen, mlenu);
        }

        // Make the uint8_t arrays
        uint8_t hexarray[mlenu];
        
        // Initialize them with zeros
        memset( hexarray, 0, sizeof(hexarray) );
        
        // Fill the uint8_t arrays
        for (int i = 0; i < mlen; i++) {
            hexarray[i] = (uint8_t)decryptedtext[i];
        }

        int messagePad = pkcs7_padding_pad_buffer(hexarray, mlen, sizeof(hexarray), 16);
        
        // In case you want to check if the padding is valid
        int valid = pkcs7_padding_valid(hexarray, mlen, sizeof(hexarray), 16);
        
        if (valid > 0) {
            printf("Is the pkcs7 padding valid message = %d\n", valid);
        }

        // Start the decryption
        AES_init_ctx_iv(&ctx, key, nonce);

        // Decrypt
        AES_CBC_decrypt_buffer(&ctx, decryptedtext, bytes_read);
        fwrite(decryptedtext, 1, mlenu, fp_decrypt);
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
