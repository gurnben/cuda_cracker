#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <cuda_runtime.h>
#include <openssl/md5.h>
#include "d_cracker.h"
#include "CHECK.h"
#include "config.h"
#include "wrappers.h"

//prototype for the kernel
__global__ void d_crack_kernel(unsigned char * hash, int hashLen,
                                int length, unsigned char * d_result);

//constant array containing all the possible characters in the password
__constant__ char VALID_CHARS[NUMCHARS];

int malloccmp(unsigned char * str1, unsigned char * str2, int length) {
  for (int i = 0; i < length; i++) {
    if (str1[i] != str2[i]) {
      return 0;
    }
  }
  return 1;
}

void printHash(unsigned char * hash, int len) {
  for (int k = 0; k < len; k++) {
    printf("%x", hash[k]);
    if (k == len - 1) {
      printf("\n");
    }
  }
}

/*d_crack
*
* Sets up and calls the kernal to brute-force a password hash.
*
* @params
*   hash    - the password hash to brute-force
*   hashLen - the length of the hash
*   outpass - the result password to return
*/
float d_crack(unsigned char * hash, int hashLen, unsigned char * outpass) {

    cudaEvent_t start_cpu, stop_cpu;
    float cpuMsecTime = -1;

    //Use cuda functions to do the timing
    //create event objects
    CHECK(cudaEventCreate(&start_cpu));
    CHECK(cudaEventCreate(&stop_cpu));
    //record the starting time
    CHECK(cudaEventRecord(start_cpu));

    int passLength = 2;
    int size = hashLen * sizeof(char);
    int outsize = MAX_PASSWORD_LENGTH * sizeof(char);
    int passoutsize = pow(NUMCHARS, passLength) * 3;

    unsigned char * d_hash;
    CHECK(cudaMalloc((void**)&d_hash, size));
    unsigned char * d_passwords;
    CHECK(cudaMalloc((void**)&d_passwords, passoutsize));
    unsigned char * d_result;
    CHECK(cudaMalloc((void**)&d_result, outsize));

    //build the const array of all lowercase characters
    char VALID_CHARS_CPU[NUMCHARS];
    for (int i = 0; i < NUMCHARS; i++) {
      VALID_CHARS_CPU[i] = (char)(i + 97);
    }
    CHECK(cudaMemcpyToSymbol(VALID_CHARS, VALID_CHARS_CPU, NUMCHARS * sizeof(char)));

    CHECK(cudaMemcpy(d_hash, hash, size, cudaMemcpyHostToDevice));

    dim3 block(NUMCHARS, 1, 1);
    dim3 grid(ceil(pow(NUMCHARS, passLength)/(float)(NUMCHARS)), 1);

    d_crack_kernel<<<grid, block>>>(d_hash, hashLen, passLength, d_passwords);

    CHECK(cudaDeviceSynchronize());

    unsigned char * passwords = (unsigned char *) Malloc(passoutsize);
    CHECK(cudaMemcpy(passwords, d_passwords, passoutsize, cudaMemcpyDeviceToHost));
    unsigned char * hashes = (unsigned char *) Malloc(pow(NUMCHARS, passLength) * hashLen);

    int j = 0;
    for (int i = 0; i < passoutsize; i+=(passLength + 1)) { //+ 1 corrects for null pointer
      // printf("%s\n", (unsigned char *) &passwords[i]); // print out generated passwords for debugging
      // printf("%lu", (unsigned long) passLength);
      MD5_CTX md5;
      MD5_Init(&md5);
      MD5_Update(&md5, &(passwords[i]), (unsigned long) passLength);
      MD5_Final(&hashes[j], &md5);
      // if (malloccmp(&passwords[i], (unsigned char *) "pa", 2)) {
      //   printHash(&hashes[j], hashLen);
      // }
      j += hashLen;
    }

    //NOTE: Hashes are forming correctly and we are getting the correct hash for input = 2

    unsigned char * ourHash = (unsigned char *) Malloc(hashLen);
    int numHashes = pow(NUMCHARS, passLength) * hashLen;
    for (int i = 0; i < numHashes; i+=hashLen) {
      // printHash(hash, hashLen);
      for (int j = 0; j < hashLen; j++) {
        ourHash[j] = hashes[i + j];
      }
      // printHash(&hashes[i], hashLen);
      // printf("%d\n", malloccmp(ourHash, hash, hashLen));
      if (malloccmp(ourHash, hash, hashLen)) {
        //TODO: Break here, we found the password
      }
      for (int k = 0; k < hashLen; k++) {
        ourHash[k] = '\0';
      }
    }
    // for (int i = 0; i < pow(NUMCHARS, passLength) * hashLen; i++) {
    //   ourHash[i % hashLen] = hashes[i];
    //   if (((i % hashLen) == 0) && malloccmp(ourHash, hashes, hashLen)) {
    //     printf("Hello");
    //     for (int j = 0; j < hashLen; j++) {
    //       printf("%x", ourHash[j]);
    //       if (j == hashLen - 1) {
    //         printf("\n");
    //       }
    //     }
    //     for (int k = 0; k < hashLen; k++) {
    //       ourHash[k] = '\0';
    //     }
    //   }
    // }

    CHECK(cudaMemcpy(outpass, d_result, outsize, cudaMemcpyDeviceToHost));

    CHECK(cudaFree(d_hash));
    CHECK(cudaFree(d_result));

    //record the ending time and wait for event to complete
    CHECK(cudaEventRecord(stop_cpu));
    CHECK(cudaEventSynchronize(stop_cpu));
    //calculate the elapsed time between the two events
    CHECK(cudaEventElapsedTime(&cpuMsecTime, start_cpu, stop_cpu));
    return cpuMsecTime;
}

/*
   d_crack_kernel
   Kernel code executed by each thread on its own data when the kernel is
   launched. Constant memory is used for the set of all possible characters,
   in this case, lowercase.
   Threads cooperate to help build a possible password built from the Constant
   character array.

   Hash - array filled with characters to crack.
   HashLen - length of the given hash
   d_result - potential password result.

*/

__global__ void d_crack_kernel(unsigned char * hash, int hashLen, int length,
                                unsigned char * d_result) {
  // printf("blockIdx: %d, blockDim: %d, threadIdx: %d\n", blockIdx.x, blockDim.x, threadIdx.x);
  unsigned char myAttempt[3];
  int index = (blockIdx.x * blockDim.x + threadIdx.x) * 3;
  d_result[index] = VALID_CHARS[blockIdx.x];
  d_result[index + 1] = VALID_CHARS[threadIdx.x];
  d_result[index + 2] = '\0';
  // printf("string: %s\n", myAttempt);
}
