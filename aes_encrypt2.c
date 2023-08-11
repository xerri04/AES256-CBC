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

    uint8_t i;
    char MESSAGE[CHUNK_SIZE];                               
    uint8_t key[32];
    uint8_t nonce[16];

    size_t bytes_read;

    randombytes_buf(nonce, sizeof(nonce));
    fwrite(nonce, sizeof(char), sizeof(nonce), fp_out);

    fread(key, 1, sizeof(key), PMK_Key);
    
    printf("key:\n");
    phex(key);
    printf("\n");

    printf("nonce:\n");
    phex(nonce);
    printf("\n");

    while ((bytes_read = fread(MESSAGE, 1, CHUNK_SIZE, fp_in)))
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
            hexarray[i] = (uint8_t)MESSAGE[i];
        }

        int messagePad = pkcs7_padding_pad_buffer(hexarray, mlen, sizeof(hexarray), 16);
        
        // In case you want to check if the padding is valid
        int valid = pkcs7_padding_valid(hexarray, mlen, sizeof(hexarray), 16);
        
        if (valid > 0) {
            printf("Is the pkcs7 padding valid message = %d\n", valid);
        }

        // Start the encryption
        AES_init_ctx_iv(&ctx, key, nonce);

        // Encrypt
        AES_CBC_encrypt_buffer(&ctx, (uint8_t *)hexarray, mlenu);
        
        fwrite(hexarray, 1, mlenu, fp_out);
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
