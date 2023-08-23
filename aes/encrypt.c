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
unsigned long long cpucycles_before, cpucycles_after, cpucycles_sum;
struct timespec begin_cpu, end_cpu, begin_wall, end_wall;

static void phex(const uint8_t *str);

// prints string as hex
static void phex(const uint8_t *str) // Use const for read-only access
{
    uint8_t len = 16;

    for (unsigned char i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

static int encrypt(const char *target_file, const char *source_file, const char *pmk_keyfile) {
    struct AES_ctx ctx;
  
    uint8_t i;                         
    uint8_t key[32];
    uint8_t nonce[16];
    char MESSAGE[CHUNK_SIZE];    

    size_t bytes_read;
    size_t rlen;

    FILE *pmk_key = fopen(pmk_keyfile, "rb");
    if (pmk_key == NULL) {
        printf("\nPMK Key with the file name [%s] cannot be found!\n", pmk_keyfile);
        return 1;
    }
    FILE *fp_s = fopen(source_file, "rb");
    if (fp_s == NULL) {
        printf("\nSource file to be encrypted with the file name [%s] cannot be found!\n", source_file);
        return 1;
    }
    FILE *fp_t = fopen(target_file, "wb");
    if (fp_t == NULL) {
        printf("\nTarget file with the file name [%s] cannot be created!\n", target_file);
        return 1;
    }

    randombytes_buf(nonce, sizeof(nonce));
    fwrite(nonce, 1, sizeof(nonce), fp_t); // Writing nonce into file
    fread(key, 1, sizeof(key), pmk_key); // Reading PMK key file

    printf("\nKey: ");
    phex(key);
    printf("Nonce: ");
    phex(nonce);

    printf("\n[*] Attempting to encrypt [%s]\n", source_file);

    clock_gettime(CLOCK_REALTIME, &begin_wall);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &begin_cpu);
    
    int mlen = bytes_read;
    int mlenu = mlen;

    while ((bytes_read = fread(MESSAGE, 1, CHUNK_SIZE, fp_s))) {
        cpucycles_reset();
        cpucycles_start();

        int mlen = bytes_read;
        int mlenu = mlen;

        if (mlen % 16) {
            mlenu += 16 - (mlen % 16);
            printf("\nThe original length of the STRING = %d and the length of the padded STRING = %d\n", mlen, mlenu);
        }

        // Make the uint8_t arrays
        uint8_t hexarray[mlenu];
        
        // Initialize them with zeros
        memset(hexarray, 0, sizeof(hexarray));
        
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

        cpucycles_stop();
        
        fwrite(hexarray, 1, mlenu, fp_t);

        total_cpucycles += cpucycles_result();
        rlen_total += bytes_read;
    }

    clock_gettime(CLOCK_REALTIME, &end_wall);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_cpu);

    fclose(pmk_key);
    fclose(fp_s);
    fclose(fp_t);
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Usage: %s <FILENAME> <ENCRYPTED_FILENAME> <KEY>\n", argv[0]);
        return 1;
    }

    if (sodium_init() < 0) {
        printf("panic! the library couldn't be initialized; it is not safe to use");
        return 1;
    }

    char *KEY_NAME = argv[1];
    char *ENCRYPTED_HACKLAB = argv[2];
    char *PMK_KEY = argv[3];

    if (encrypt(ENCRYPTED_HACKLAB, KEY_NAME, PMK_KEY) != 0) {
        return 1;
    }

  printf("\n[+] [%s] encrypted to [%s] successfully\n", KEY_NAME, ENCRYPTED_HACKLAB);

  double total_time_cpu = (end_cpu.tv_sec - begin_cpu.tv_sec) + (end_cpu.tv_nsec - begin_cpu.tv_nsec) / 1000000000.0;
  double total_time_wall = (end_wall.tv_sec - begin_wall.tv_sec) + (end_wall.tv_nsec - begin_wall.tv_nsec) / 1000000000.0;

  printf("\nWALL time: %f seconds\n", total_time_wall);
  printf("CPU time: %f seconds\n", total_time_cpu);

  printf("\nTotal CPU Cycles: %.0f\n", total_cpucycles);
  printf("CPU Cycles/Bytes: %f\n", total_cpucycles / rlen_total);

    return 0;
}
