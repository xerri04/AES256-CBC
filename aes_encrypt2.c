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

    uint8_t i;
    char MESSAGE[CHUNK_SIZE];                               
    char key[32];
    char nonce[16];

    fseek(fp_in, 0, SEEK_END);
    int mlen = ftell(fp_in);
    fseek(fp_in, 0, SEEK_SET);

    randombytes_buf(nonce, 16);
    int nlen = strlen(nonce);
    fwrite(nonce, sizeof(char), sizeof(nonce), fp_out);

    fread(key, 1, 32, PMK_Key);
    int klen = strlen(key);
    
    printf("key:\n");
    phex(key);
    printf("\n");

    printf("nonce:\n");
    phex(nonce);
    printf("\n");

    // Proper length of message, key and nonce
    int mlenu = mlen;
    if (mlen % 16) {
        mlenu += 16 - (mlen % 16);
        printf("The original length of the STRING = %d and the length of the padded STRING = %d\n", mlen, mlenu);
    }

    int klenu = klen;
    if (klen % 16) {
        klenu += 16 - (klen % 16);
        printf("The original length of the KEY = %d and the length of the padded KEY = %d\n", klen, klenu);
    }

    int nlenu = nlen;
    if (nlen % 16) {
        nlenu += 16 - (nlen % 16);
        printf("The original length of the NONCE = %d and the length of the padded NONCE = %d\n", nlen, nlenu);
    }

    // Make the uint8_t arrays
    uint8_t hexarray[mlenu];
    uint8_t kexarray[klenu];
    uint8_t nexarray[nlenu];
    
    // Initialize them with zeros
    memset( hexarray, 0, sizeof(hexarray) );
    memset( kexarray, 0, sizeof(kexarray) );
    memset( nexarray, 0, sizeof(nexarray) );
    
    // Fill the uint8_t arrays
    for (int i = 0; i < mlen; i++) {
        hexarray[i] = (uint8_t)MESSAGE[i];
    }

    for (int i = 0; i < klen; i++) {
        kexarray[i] = (uint8_t)key[i];
    }
    
    for (int i = 0; i < nlen; i++) {
        nexarray[i] = (uint8_t)nonce[i];
    }

    int messagePad = pkcs7_padding_pad_buffer( hexarray, mlen, sizeof(hexarray), 16 );
    int keyPad = pkcs7_padding_pad_buffer( kexarray, klen, sizeof(kexarray), 16 );
    int noncePad = pkcs7_padding_pad_buffer( nexarray, nlen, sizeof(nexarray), 16 );
    
    // In case you want to check if the padding is valid
    int valid = pkcs7_padding_valid( hexarray, mlen, sizeof(hexarray), 16 );
    int valid2 = pkcs7_padding_valid( kexarray, klen, sizeof(kexarray), 16 );
    int valid3 = pkcs7_padding_valid( nexarray, nlen, sizeof(nexarray), 16 );
    printf("Is the pkcs7 padding valid message = %d  |  key = %d  |  nonce = %d\n", valid, valid2, valid3);

    size_t bytes_read;

    while ((bytes_read = fread(hexarray, 1, CHUNK_SIZE, fp_in)))
    {
        // Start the encryption
        AES_init_ctx_iv(&ctx, (const uint8_t *)kexarray, (const uint8_t *)nexarray);

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
