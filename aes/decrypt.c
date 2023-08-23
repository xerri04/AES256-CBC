#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <x86intrin.h>
#include <unistd.h>

#include "./lib/aes.h"
#include "./lib/pkcs7_padding.h"
#include "./lib/pkcs7_padding.c"

#define CBC 1
#define CHUNK_SIZE 4096

#define cpucycles(cycles) cycles = __rdtsc()

#define cpucycles_reset() cpucycles_sum = 0
#define cpucycles_start() cpucycles(cpucycles_before)
#define cpucycles_stop()                                 \
do {                                                   \
    cpucycles(cpucycles_after);                          \
    cpucycles_sum += cpucycles_after - cpucycles_before; \
} while (0)

#define cpucycles_result() cpucycles_sum

size_t rlen_total;
double total_cpucycles;
struct timespec begin_cpu, end_cpu, begin_wall, end_wall;
unsigned long long cpucycles_before, cpucycles_after, cpucycles_sum;

static void phex(const uint8_t *str);

// prints string as hex
static void phex(const uint8_t *str) // Use const for read-only access
{
    uint8_t len = 16;

    for (unsigned char i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}


static int decrypt(const char *target_file, const char *source_file, const char *pmk_keyfile) {
    struct AES_ctx ctx;

    uint8_t i;
    char decryptedtext[CHUNK_SIZE];                               
    uint8_t key[32];
    uint8_t nonce[16];

    unsigned long long out_len;
    size_t  rlen;

    FILE *pmk_key = fopen(pmk_keyfile, "rb");
    if (pmk_key == NULL) {
        printf("\nPMK Key with the file name [%s] cannot be found!\n", pmk_keyfile);
        return 1;
    }

    FILE *fp_s = fopen(source_file, "rb");
    if (fp_s == NULL) {
        printf("\nSource file to be dencrypted with the file name [%s] cannot be found!\n", source_file);
        return 1;
    }

    FILE *fp_t = fopen(target_file, "wb");
    if (fp_t == NULL) {
        printf("\nTarget file with the file name [%s] cannot be created!\n", target_file);
        return 1;
    }

    fread(nonce, sizeof(char), sizeof(nonce), fp_s);
    fread(key, 1, sizeof(key), pmk_key);
    
    printf("\nkey: ");
    phex(key);

    printf("nonce: ");
    phex(nonce);

    printf("\n[*] Attempting to decrypt [%s]\n", source_file);

    clock_gettime(CLOCK_REALTIME, &begin_wall);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &begin_cpu);

    int padlen;

    size_t bytes_read;
    while ((bytes_read = fread(decryptedtext, 1, CHUNK_SIZE, fp_s))) {
        
        int mlen = bytes_read;
        int mlenu = mlen;

        cpucycles_reset();
        cpucycles_start();

        if (mlen % 16) {
            mlenu += 16 - (mlen % 16);
            printf("The original length of the STRING = %d and the length of the padded STRING = %d\n", mlen, mlenu);
        }

        // Make the uint8_t arrays
        uint8_t hexarray[mlenu];
        
        // Initialize them with zeros
        memset(hexarray, 0, sizeof(hexarray));
        
        // Fill the uint8_t arrays
        for (int i = 0; i < mlen; i++) {
            hexarray[i] = (uint8_t)decryptedtext[i];
        }

        // Start the decryption
        AES_init_ctx_iv(&ctx, key, nonce);

        // Decrypt
        AES_CBC_decrypt_buffer(&ctx, hexarray, mlenu);

        // Determine the padding length
        padlen = pkcs7_padding_data_length(hexarray, mlenu, 16);

        /*
        for (i=0; i<padlen; i++){   
            printf("%02x",hexarray[i]);
  
        }
        */

        if (padlen != 0) {
            mlenu = padlen;
        }

        /*
        if (CHUNK_SIZE > padlen && padlen > 0) {
            mlenu = padlen;
        }
        */

        cpucycles_stop();

        // Write the decrypted data without padding
        fwrite(hexarray, 1, mlenu, fp_t);

        total_cpucycles += cpucycles_result();
        rlen_total += bytes_read;
    }

    /*
    printf("\npadlen: %d\n", padlen);

    fseek(fp_s, 0, SEEK_END);
    long current_size = ftell(fp_s);
    fseek(fp_s, 0, SEEK_SET);

    int new_size = current_size - (current_size - ((CHUNK_SIZE * (current_size / CHUNK_SIZE)) + padlen));

    printf("\nnew size: %d\n", new_size);

    fseek(fp_t, 0, SEEK_END);

    ftruncate(fileno(fp_t), new_size);
    */

    clock_gettime(CLOCK_REALTIME, &end_wall);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_cpu);

    fclose(fp_t);
    fclose(fp_s);
    fclose(pmk_key);
    return 0;
}

int main(int argc, char *argv[]) {

    if (argc != 4) {
        printf("Usage: %s <ENCRYPTED_FILENAME> <PLAINTEXT_FILENAME> <KEY>\n", argv[0]);
        return 1;
    }

    char *ENCRYPTED_HACKLAB = argv[1];
    char *KEY_NAME = argv[2];
    char *PMK_KEY = argv[3];

    if (decrypt(KEY_NAME, ENCRYPTED_HACKLAB, PMK_KEY) != 0) {
        return 1;
    }
    
    printf("\n[+] [%s] decrypted to [%s] successfully\n", ENCRYPTED_HACKLAB, KEY_NAME);

    double total_time_cpu = (end_cpu.tv_sec - begin_cpu.tv_sec) + (end_cpu.tv_nsec - begin_cpu.tv_nsec) / 1000000000.0;
    double total_time_wall = (end_wall.tv_sec - begin_wall.tv_sec) + (end_wall.tv_nsec - begin_wall.tv_nsec) / 1000000000.0;

    printf("\nWALL time: %f seconds\n", total_time_wall);
    printf("CPU time: %f seconds\n", total_time_cpu);

    printf("\nTotal CPU Cycles: %.0f\n", total_cpucycles);
    printf("CPU Cycles/Bytes: %f\n", total_cpucycles / rlen_total);

    return 0;
}
