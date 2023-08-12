#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <x86intrin.h>
#include <unistd.h>

#include "aes.h"
#include "pkcs7_padding.c"

#define CBC 1
#define CHUNK_SIZE 1024

#define cpucycles(cycles) cycles = __rdtsc()

#define cpucycles_reset() cpucycles_sum = 0
#define cpucycles_start() cpucycles(cpucycles_before)
#define cpucycles_stop()                                 \
do {                                                   \
    cpucycles(cpucycles_after);                          \
    cpucycles_sum += cpucycles_after - cpucycles_before; \
} while (0)

#define cpucycles_result() cpucycles_sum

unsigned long long cpucycles_before, cpucycles_after, cpucycles_sum;

static void phex(const uint8_t *str);

long get_mem_usage()
{
  struct rusage myusage;

  getrusage(RUSAGE_SELF, &myusage);
  return myusage.ru_maxrss;
}

int main(int argc, char *argv[])
{
    if (sodium_init() < 0)
    {
        printf("panic! the library couldn't be initialized; it is not safe to use");
        return 1;
    }

    struct AES_ctx ctx;

    FILE *fp_in, *fp_out, *PMK_Key;

    if (strcmp(argv[1], "secret") == 0) {
        fp_in = fopen("secret.key", "rb");
        fp_out = fopen("secret.key.hacklab", "wb");
    }

    else if (strcmp(argv[1], "pub") == 0) {
        fp_in = fopen("public.key", "rb");
        fp_out = fopen("public.key.hacklab", "wb");
    }

    else if (strcmp(argv[1], "nbit") == 0) {
        fp_in = fopen("nbit.key", "rb");
        fp_out = fopen("nbit.key.hacklab", "wb");
    }

    else {
        printf("\n%s is not a valid argument\n", argv[1]);
        return 0;
    }

    if (fp_in == NULL)
    {
        printf("Error opening key to encrypt.\n");
        return 1;
    }

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

    printf("[*] Attempting to encrypt public key\n\n");

    long baseline = get_mem_usage();

    unsigned int counter;
    unsigned long long min=-1, max=0, total_bytes=0, total_cpu_cycle=0;
    double total_time;
    
    FILE *cpu_cycle_file = fopen("cpu_cycle_encrypt.txt", "w");
    struct timespec begin, end;

    while ((bytes_read = fread(MESSAGE, 1, CHUNK_SIZE, fp_in)))
    {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &begin);

        cpucycles_reset();
        cpucycles_start();

        int mlen = bytes_read;
        int mlenu = mlen;

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

        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
        
        fwrite(hexarray, 1, mlenu, fp_out);

        double time_spent = (end.tv_sec - begin.tv_sec) + (end.tv_nsec - begin.tv_nsec) / 1000000000.0;

        if(bytes_read == CHUNK_SIZE){
        uint64_t current = cpucycles_result();

        fprintf(cpu_cycle_file, "%ld  %f\n", current, time_spent);

        total_cpu_cycle += current;
        if(current > max){
            max = current;
        }
        if(current < min){
            min = current;
        }

        total_time += time_spent;
        counter ++;
        } 
    }

    printf("\n[+] Public key encrypted\n");
    
    total_bytes = counter * CHUNK_SIZE;

    printf("\nChunksize is: %i\n", CHUNK_SIZE);
    printf("Minimum CPU Cycles/Bytes: %.3f\n", (float)min/CHUNK_SIZE);
    printf("Maximum CPU Cycles/Bytes: %.3f\n", (float)max/CHUNK_SIZE);
    printf("Average CPU Cycles/Bytes: %.3f\n", (float)total_cpu_cycle/total_bytes);
    
    printf("\nTotal CPU time: %f seconds\n", total_time);
    printf("Total CPU Cycles/Bytes per second: %.3f \n", (float)total_cpu_cycle/total_bytes/total_time);

    fclose(fp_in);
    fclose(fp_out);
    fclose(PMK_Key);
    fclose(cpu_cycle_file);

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